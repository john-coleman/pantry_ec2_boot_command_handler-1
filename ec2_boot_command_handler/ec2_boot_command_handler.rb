require 'aws-sdk'
require 'erb'
require 'active_support/core_ext/hash/keys'
require 'timeout'

module Wonga
  module Daemon
    class EC2BootCommandHandler
      def initialize(ec2 = AWS::EC2.new, publisher, logger)
        @ec2 = ec2
        @publisher = publisher
        @logger = logger
      end

      def find_machine_by_request_id(request_id)
        @ec2.instances.filter('tag:pantry_request_id', [request_id.to_s]).first
      end      

      def handle_message(message)
        instance = find_machine_by_request_id(message["pantry_request_id"])
        if instance
          case instance.status 
          when :pending
            @logger.info("Instance #{message["pantry_request_id"]} - name: #{message["name"]} machine boot still pending")
            raise 
          when :running
            @logger.info("Instance #{message["pantry_request_id"]} - name: #{message["name"]} running, publishing")            
            @publisher.publish(message.merge(
              {
                instance_id: instance.id,
                instance_ip: instance.private_ip_address
              })
            )
          else
            @logger.error("Instance #{message["pantry_request_id"]} - name: #{message["name"]} unexpected state: #{instance.status}")
          end
        else
          instance = request_instance(message)
          raise if tag_instance!(instance, message)
        end
        @logger.error("Unexpected state encountered")
      end    

      def render_user_data(msg)
        template = IO.read(File.join(File.dirname(__FILE__),"..","templates","user_data_windows.erb"))
        ERB.new(template, nil, "<>").result(msg.instance_eval{binding})
      end      

      def request_instance(message)
        @ec2.instances.create(
          image_id:                 message["ami"],
          instance_type:            message["flavor"],
          key_name:                 message["aws_key_pair_name"],
          subnet:                   message["subnet_id"],          
          disable_api_termination:  message["protected"],
          block_device_mappings:    message["block_device_mappings"].map{|hash| hash.deep_symbolize_keys },
          security_group_ids:       Array(message["secgroup_ids"]),
          user_data:                render_user_data(message),
          count:                    1
        )
      end

      def tag_instance!(instance, message)
        tags = {
          'Name'              => "#{message["instance_name"]}.#{message["domain"]}", 
          'team_id'           => message['team_id'].to_s,
          'pantry_request_id' => message['pantry_request_id'].to_s
        }
      
        instance.tags.set(tags)
        instance.tags["pantry_request_id"] == message["pantry_request_id"].to_s
       rescue Exception => e 
          @logger.error("Instance #{message["pantry_request_id"]} - name: #{message["name"]} failed to tag with error: #{e}")
       end
    end
  end
end

