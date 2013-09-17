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

      def handle_message(message)
        if machine = find_machine_by_request_id(message["pantry_request_id"])
          @logger.warn "Machine request #{message["pantry_request_id"]} already booted"
        else
          @logger.warn "Attempting to boot machine with id: #{message["pantry_request_id"]}"
          user_data = render_user_data(message)
          @logger.debug "User data #{user_data}"
          machine = boot_machine(
            message["pantry_request_id"],
            message["instance_name"],
            message["domain"],
            message["flavor"],
            message["ami"],
            message["team_id"],
            message["subnet_id"],
            message["security_group_ids"],
            message["aws_key_pair_name"],
            message["block_device_hash"],
            user_data
          )
        end

        raise_machine_booted_event(
          message,
          machine.id,
          machine.private_ip_address
        )
      end

      def render_user_data(msg)
        template = IO.read(File.join(File.dirname(__FILE__),"..","templates","user_data_windows.erb"))
        user_data = ERB.new(template, nil, "<>").result(msg.instance_eval{binding})
      end

      def raise_machine_booted_event(message_in, instance_id, instance_ip)
        message_out = message_in.merge(
          {instance_id: instance_id, private_ip: instance_ip}
        )
        @publisher.publish(message_out)
      end

      def boot_machine(request_id, instance_name, domain, flavor, ami, team_id, subnet_id, secgroup_ids, key_name, block_device_hash, user_data)
        instance = create_instance(ami, flavor, secgroup_ids, subnet_id, key_name, block_device_hash, user_data)
        tag_and_wait_instance(instance, request_id, instance_name, domain, team_id)
      end

      def create_instance(ami, flavor, secgroup_ids, subnet_id, key_name, block_device_hash, user_data)
        @ec2.instances.create(
          image_id:               ami,
          instance_type:          flavor,
          count:                  1,
          security_group_ids:     Array(secgroup_ids),
          subnet:                 subnet_id,
          key_name:               key_name,
          user_data:              user_data,
          block_device_mappings:  block_device_hash
        )
      end

      def find_machine_by_request_id(request_id)
        @ec2.instances.filter('tag:pantry_request_id', [request_id.to_s]).first
      end

      def tag_and_wait_instance(instance, request_id, instance_name, domain, team_id)
        @ec2.client.create_tags(
          resources: [instance.id],
          tags: 
          [
            { key: "Name",              value: "#{instance_name}.#{domain}"  },
            { key: "team_id",           value: "#{team_id}"   },
            { key: "pantry_request_id", value: "#{request_id}"}
          ]
        )

        @logger.warn "instance status: pending"
        previous_status = nil
        status = Timeout.timeout(300) {
          while true do
            begin
              response = @ec2.client.describe_instance_status(instance_ids: [instance.id])
              instance_status = response.data[:instance_status_set][0][:instance_status][:status]
            rescue
              sleep(3)
              retry
            end

            if instance_status != previous_status
              @logger.warn "Instance status: #{instance_status}"
              previous_status = instance_status
            end

            if instance_status == "ok"
              return instance
            elsif instance_status != "initializing"
              @logger.error "Unexpected EC2 status return: #{instance_status}"
              raise "Unexpected EC2 status return: #{instance_status}"
            end
            sleep(3)
          end
        }
      end
    end
  end
end

