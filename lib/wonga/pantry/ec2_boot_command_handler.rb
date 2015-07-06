require 'erb'
require 'active_support/core_ext/hash/keys'
require 'timeout'

module Wonga
  module Pantry
    class EC2BootCommandHandler
      def initialize(ec2 = Aws::EC2::Resource.new, config, publisher, error_publisher, logger)
        @ec2 = ec2
        @config = config
        @publisher = publisher
        @error_publisher = error_publisher
        @logger = logger
      end

      def find_machine_by_request_id(request_id)
        @ec2.instances(filters: [{ name: 'tag:pantry_request_id', values: [request_id.to_s] }]).first
      end

      def handle_message(message)
        instance = find_machine_by_request_id(message['pantry_request_id'])
        if instance
          case instance.state.name
          when 'terminated'
            send_error_message(message)
            return
          when 'stopping', 'stopped', 'shutting_down'
            @logger.error("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} is #{instance.state.name}")
            fail
          when 'pending'
            @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} is #{instance.state.name}")
            fail
          when 'running'
            @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} is #{instance.state.name}")
            tag_volumes!(instance, message)
            @publisher.publish(message.merge(instance_id: instance.id, ip_address: instance.private_ip_address, private_ip: instance.private_ip_address))
            return
          else
            @logger.error("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} "\
                          "unexpected state: #{instance.state.name}")
            fail
          end
        else
          instance = request_instance(message)
          @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} requested")
          if tag_instance!(instance, message)
            @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} tagged")
            fail
          else
            fail Exception, 'Instance tagging failed'
          end
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
          subnet_id:                message['subnet_id'],
          disable_api_termination:  message['protected'],
          block_device_mappings:    message['block_device_mappings'].map(&:deep_symbolize_keys),
          security_group_ids:       Array(message['security_group_ids']),
          user_data:                render_user_data(message),
          min_count:                1,
          max_count:                1
        }
        params = params.merge(iam_instance_profile: { name: message['iam_instance_profile'] }) if message['iam_instance_profile']
        @ec2.create_instances(params).first
      end

      def tag_instance!(instance, message)
        i = 0
        begin
          tags = tags_from_message(message)
          @ec2.create_tags resources: [instance.id], tags: tags
          instance.reload
          instance.tags.any? { |hash| hash['key'] = 'pantry_request_id' && hash['value'] == message['pantry_request_id'].to_s }
        rescue Aws::Errors::ServiceError => e
          i += 1
          if i < @config['retries'].to_i
            sleep @config['retry_delay'].to_i + 1
            retry
          end
          @logger.error("Instance #{message['pantry_request_id']} - name: #{message['name']} #{instance.id} failed to tag with error: #{e.inspect}")
          @logger.error(e.backtrace.to_s)
          false
        end
      end

      def tag_volumes!(instance, message)
        volume_count = 1
        instance.volumes.each do |volume|
          device = volume.attachments.first.device
          tags = if device == '/dev/sda1'
                   tags_from_message message, '_OS_VOL'
                 else
                   volume_count += 1
                   tags_from_message message, "_VOL#{volume_count}"
                 end

          vol_tags = tags << { key: 'device', value: device }
          @ec2.create_tags resources: [volume.id], tags: vol_tags
        end
        @logger.info("Instance #{message['pantry_request_id']} - name: #{message['instance_name']} #{instance.id} volumes tagged")
      end

      def tags_from_message(message, additional_name = '')
        [
          { key: 'Name', value: "#{message['instance_name']}.#{message['domain']}#{additional_name}" },
          { key: 'pantry_request_id', value: message['pantry_request_id'].to_s },
          { key: 'shutdown_schedule', value: message['shutdown_schedule'] || @config['shutdown_schedule'] },
          { key: 'team_id', value: message['team_id'].to_s },
          { key: 'team_name', value: message['team_name'].to_s }
        ]
      end
    end
  end
end
