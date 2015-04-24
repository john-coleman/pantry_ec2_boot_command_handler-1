require 'aws-sdk-v1'
require 'erb'
require 'active_support/core_ext/hash/keys'
require 'timeout'

module Wonga
  module Pantry
    class EC2BootCommandHandler
      def initialize(ec2 = AWS::EC2.new, config, publisher, error_publisher, logger)
        @ec2 = ec2
        @config = config
        @publisher = publisher
        @error_publisher = error_publisher
        @logger = logger
      end

      def find_machine_by_request_id(request_id)
        @ec2.instances.filter('tag:pantry_request_id', [request_id.to_s]).first
      end

      def handle_message(message)
        instance = find_machine_by_request_id(message['pantry_request_id'])
        if instance
          case instance.status
          when :terminated
            send_error_message(message)
            return
          when :stopping, :stopped, :shutting_down
            @logger.error("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} is #{instance.status}")
            fail
          when :pending
            @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} is #{instance.status}")
            fail
          when :running
            @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} is #{instance.status}")
            fail unless tag_volumes!(instance, message)
            @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} volumes tagged")
            @publisher.publish(message.merge(instance_id: instance.id,
                                             ip_address: instance.private_ip_address,
                                             private_ip: instance.private_ip_address
                                            )
                              )
            return
          else
            @logger.error("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} unexpected state: #{instance.status}")
            fail
          end
        else
          instance = request_instance(message)
          @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} requested")
          tag_instance!(instance, message)
          @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} tagged")
          fail
        end
        @logger.error('Unexpected WTF state encountered!')
        fail
      end

      def send_error_message(message)
        @logger.info 'Send request to cleanup an instance'
        @error_publisher.publish(message)
      end

      def render_user_data(message)
        template = IO.read(File.join(File.dirname(__FILE__), '..', '..', '..', 'templates', "user_data_#{message['platform']}.erb"))
        ERB.new(template, nil, '<>').result(message.instance_eval { binding })
      end

      def request_instance(message)
        params = {
          image_id:                 message['ami'],
          instance_type:            message['flavor'],
          key_name:                 message['aws_key_pair_name'],
          subnet:                   message['subnet_id'],
          disable_api_termination:  message['protected'],
          block_device_mappings:    message['block_device_mappings'].map(&:deep_symbolize_keys),
          security_group_ids:       Array(message['security_group_ids']),
          user_data:                render_user_data(message),
          count:                    1
        }
        params = params.merge(iam_instance_profile: message['iam_instance_profile']) if message['iam_instance_profile']
        @ec2.instances.create(params)
      end

      def tag_instance!(instance, message)
        i = 0
        begin
          tags = tags_from_message(message)
          instance.tags.set(tags)
          instance.tags['pantry_request_id'] == message['pantry_request_id'].to_s
        rescue Exception => e # rubocop:disable Lint/RescueException
          i += 1
          if i < @config['retries'].to_i
            sleep @config['retry_delay'].to_i
            retry
          end
          @logger.error("Instance #{message['pantry_request_id']} - name: #{message['name']} #{instance.id} failed to tag with error: #{e.inspect}")
          @logger.error(e.backtrace.to_s)
          false
        end
      end

      def tag_volumes!(instance, message)
        tags = tags_from_message(message)
        volume_count = 1
        instance.attachments.each do |device, attachment|
          if device == '/dev/sda1'
            vol_name = tags['Name'] + '_OS_VOL'
          else
            vol_name = tags['Name'] + "_VOL#{volume_count}"
            volume_count += 1
          end

          vol_tags = tags.merge('Name' => vol_name, 'device' => device)
          attachment.volume.tags.set(vol_tags)
        end
      end

      def tags_from_message(message)
        {
          'Name'              => "#{message['instance_name']}.#{message['domain']}",
          'pantry_request_id' => message['pantry_request_id'].to_s,
          'shutdown_schedule' => message['shutdown_schedule'] || @config['shutdown_schedule'],
          'team_id'           => message['team_id'].to_s,
          'team_name'         => message['team_name'].to_s
        }
      end
    end
  end
end
