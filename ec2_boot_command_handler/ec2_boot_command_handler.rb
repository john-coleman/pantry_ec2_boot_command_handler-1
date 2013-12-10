require 'aws-sdk'
require 'erb'
require 'timeout'

module Wonga
  module Daemon
    class EC2BootCommandHandler
      def initialize(publisher, logger)
        @ec2 = AWS::EC2.new
        @publisher = publisher
        @logger = logger
      end

      def find_machine_by_request_id(request_id)
        @ec2.instances.filter('tag:pantry_request_id', [request_id.to_s]).first
      end      

      def handle_message(message)
        instance = find_machine_by_request_id(message["pantry_request_id"])
        if instance
          begin
            response = @ec2.client.describe_instance_status(instance_ids: [instance.id])
            status = response.data[:instance_status_set][0][:instance_status][:status]
          rescue
            @logger.info("Instance #{message["pantry_request_id"]} - name: #{message["name"]} response still pending")            
            raise            
          end

          case status 
          when "initializing"
            @logger.info("Instance #{message["pantry_request_id"]} - name: #{message["name"]} machine boot still pending")
            raise 
          when "ok"
            @logger.info("Instance #{message["pantry_request_id"]} - name: #{message["name"]} running, publishing")            
            @publisher.publish(message.merge(
              {
                instance_id: instance.id,
                instance_ip: instance.private_ip_address
              })
            )
            return
          else
            @logger.error("Instance #{message["pantry_request_id"]} - name: #{message["name"]} unexpected state: #{status}")
          end

        else
          instance = request_instance(message)
          tag_instance(instance, message)
          raise
        end
        @logger.error("Unexpected state encountered")
      end      

      def device_hash_keys_to_symbols(hash)
        return hash unless hash.is_a?(Hash)
        result = hash.each_with_object({}) do |(k,v), new|
          new[k.to_sym] = device_hash_keys_to_symbols(v)
        end
      end      

      def render_user_data(msg)
        template = IO.read(File.join(File.dirname(__FILE__),"..","templates","user_data_windows.erb"))
        ERB.new(template, nil, "<>").result(msg.instance_eval{binding})
      end      

      def request_instance(message)
        user_data = render_user_data(message)
        @ec2.instances.create(
          image_id:                 message["ami"],
          instance_type:            message["flavor"],
          key_name:                 message["aws_key_pair_name"],
          subnet:                   message["subnet_id"],          
          disable_api_termination:  message["protected"],
          block_device_mappings:    message["block_device_mappings"].map{|i| device_hash_keys_to_symbols(i) },
          security_group_ids:       Array(message["secgroup_ids"]),
          user_data:                user_data,
          count:                    1
        )
      end

      def tag_instance(instance, message)
        @ec2.client.create_tags(
          resources: [instance.id],
          tags: 
          [
            { key: "Name",              value: "#{message["instance_name"]}.#{message["domain"]}"  },
            { key: "team_id",           value: "#{message["team_id"]}"   },
            { key: "pantry_request_id", value: "#{message["request_id"]}"}
          ]
        )
      end
    end
  end
end

