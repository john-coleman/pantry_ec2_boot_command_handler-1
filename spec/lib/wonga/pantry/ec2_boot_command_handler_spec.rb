require 'logger'
require 'wonga/daemon/publisher'
require_relative '../../../../lib/wonga/pantry/ec2_boot_command_handler'

RSpec.describe Wonga::Pantry::EC2BootCommandHandler do
  let(:logger) { instance_double(Logger).as_null_object }
  let(:publisher) { instance_double(Wonga::Daemon::Publisher, publish: message) }
  let(:error_publisher) { instance_double(Wonga::Daemon::Publisher, publish: message) }
  let(:request_id) { 2 }
  let(:retry_count) { 0 }
  let(:config) do
    {
      'no_proxy_domains' => 'no-proxy.example.com',
      'retries' => retry_count,
      'shutdown_schedule' => 'never'
    }
  end
  let(:message) do
    {
      'ami' => 'ami-fedfd48a',
      'aws_key_pair_name' => 'eu-test-1',
      'block_device_mappings' => [
        {
          virtual_name: 'some string',
          device_name: 'some string',
          ebs: {
            snapshot_id: 'some ide'
          }
        }
      ],
      'domain' => 'example.com',
      'flavor' => 't1.micro',
      'instance_name' => 'sqs-test',
      'pantry_request_id' => request_id,
      'platform' => 'windows',
      'protected' => false,
      'security_group_ids' => ['sg-f94dc88e'],
      'subnet_id' => 'subnet-f3c63a98',
      'team_id' => '000',
      'team_name' => 'test team'
    }
  end
  let(:ec2_resource) { Aws::EC2::Resource.new }

  subject { described_class.new(config, publisher, error_publisher, logger, ec2_resource) }

  it_behaves_like 'handler'

  describe '#handle_message' do
    context 'when instance does not exist' do
      let(:instance_response) { { reservations: [{ instances: [instance_attributes] }] } }
      let(:instance_attributes) { { tags: [key: 'pantry_request_i', value: request_id.to_s] } }
      let(:response) { { reservations: [] } }
      let(:create_response) { { instance_id: 'test' } }

      before(:each) do
        ec2_resource.client.stub_responses(:run_instances, instances: [create_response])
        ec2_resource.client.stub_responses(:describe_instances, response, instance_response)
        ec2_resource.client.stub_responses :create_tags
      end

      it 'requests instance' do
        expect(ec2_resource.client).to receive(:run_instances).and_call_original
        expect { subject.handle_message(message) }.to raise_error RuntimeError
      end

      it 'tags instance' do
        expect(ec2_resource.client).to receive(:create_tags).and_wrap_original do |original, hash, &block|
          expect(hash[:resources]).to eq ['test']
          request_hash = hash[:tags].detect { |h| h[:key] == 'pantry_request_id' }
          expect(request_hash[:value]).to eq request_id.to_s
          original.call(hash, &block)
        end
        expect { subject.handle_message(message) }.to raise_error RuntimeError
      end

      context 'when message contains iam_instance_profile' do
        let(:message) do
          super().merge('iam_instance_profile' => profile)
        end

        let(:profile) { 'test_iam' }

        it 'requests an instance with iam' do
          expect(ec2_resource.client).to receive(:run_instances).with(hash_including(iam_instance_profile: { name: profile })).and_call_original
          expect { subject.handle_message(message) }.to raise_error RuntimeError
        end
      end

      context 'when no proxy attribute is provided' do
        it 'requests instance without proxy' do
          expect(ec2_resource.client).to receive(:run_instances).and_wrap_original do |original, *args, &block|
            expect(Base64.decode64(args[0][:user_data])).not_to match(/SETX HTTP_PROXY/)
            original.call(*args, &block)
          end

          expect { subject.handle_message(message) }.to raise_error RuntimeError
        end
      end

      context 'when proxy attribute is provided' do
        let(:message_proxy) { message.merge('http_proxy' => 'http://proxy.herp.derp:0') }

        it 'requests instance with proxy' do
          expect(ec2_resource.client).to receive(:run_instances).and_wrap_original do |original, *args, &block|
            expect(Base64.decode64(args[0][:user_data])).to match(/SETX HTTP_PROXY/)
            expect(Base64.decode64(args[0][:user_data])).to match("SETX NO_PROXY \"#{message['domain']},#{config['no_proxy_domains']}\" /M")
            original.call(*args, &block)
          end

          expect { subject.handle_message(message_proxy) }.to raise_error RuntimeError
        end
      end

      context 'when Linux platform specified' do
        let(:message_linux)   { message.merge('platform' => 'linux') }

        it 'requests instance with hostname set in user_data' do
          expect(ec2_resource.client).to receive(:run_instances).and_wrap_original do |original, *args, &block|
            expect(Base64.decode64(args[0][:user_data])).to include("hostname #{message['instance_name']}")
            expect(Base64.decode64(args[0][:user_data])).to include("#{message['instance_name']}.#{message['domain']}")
            original.call(*args, &block)
          end

          expect { subject.handle_message(message_linux) }.to raise_error RuntimeError
        end
      end

      context 'when shutdown schedule specified' do
        let(:message_shutdown) { message.merge('shutdown_schedule' => 'sometimes') }

        it 'tags requested instance and raises exception' do
          expect(ec2_resource.client).to receive(:create_tags).and_wrap_original do |original, hash, &block|
            expect(hash[:resources]).to eq ['test']
            request_hash = hash[:tags].detect { |h| h[:key] == 'shutdown_schedule' }
            expect(request_hash[:value]).to eq 'sometimes'
            original.call(hash, &block)
          end
          expect { subject.handle_message(message_shutdown) }.to raise_error RuntimeError
        end
      end

      context 'when no shutdown schedule specified' do
        context 'when default schedule specified in config' do
          let(:config) { { 'retries' => retry_count, 'shutdown_schedule' => 'everyday' } }
          it 'tags with default schedule' do
            expect(ec2_resource.client).to receive(:create_tags).and_wrap_original do |original, hash, &block|
              expect(hash[:resources]).to eq ['test']
              request_hash = hash[:tags].detect { |h| h[:key] == 'shutdown_schedule' }
              expect(request_hash[:value]).to eq 'everyday'
              original.call(hash, &block)
            end
            expect { subject.handle_message(message) }.to raise_error RuntimeError
          end
        end

        it 'tags requested instance' do
          expect(ec2_resource.client).to receive(:create_tags).and_wrap_original do |original, hash, &block|
            expect(hash[:resources]).to eq ['test']
            request_hash = hash[:tags].detect { |h| h[:key] == 'shutdown_schedule' }
            expect(request_hash[:value]).to eq 'never'
            original.call(hash, &block)
          end
          expect { subject.handle_message(message) }.to raise_error RuntimeError
        end
      end

      context "when instance can't be requested" do
        it 'raise exception' do
          ec2_resource.client.stub_responses(:run_instances, 'ServiceError')
          expect { subject.handle_message(message) }.to raise_error Aws::Errors::ServiceError
        end
      end

      context 'when instance not tagged' do
        let(:retry_count) { 10 }

        it 'retries before reraising exception' do
          ec2_resource.client.stub_responses(:create_tags, 'ServiceError')
          expect(ec2_resource.client).to receive(:create_tags).exactly(10).times.and_call_original
          allow(subject).to receive(:sleep)
          expect { subject.handle_message(message) }.to raise_error Exception
        end
      end
    end
  end

  context 'when instance is requested' do
    let(:instance_ip) { '192.168.13.37' }
    let(:instance_id) { 'i-fake1337' }
    let(:response) { { reservations: [{ instances: [{ instance_id: instance_id, state: { name: ec2_status }, private_ip_address: instance_ip }] }] } }

    before(:each) do
      expect(ec2_resource.client).not_to receive(:run_instances)
      ec2_resource.client.stub_responses(:describe_instances, response)
    end

    context "when instance can't return current status" do
      let(:ec2_status) { nil }
      it 'raises exception' do
        expect { subject.handle_message message }.to raise_error RuntimeError
      end
    end

    context "when instance's status is pending" do
      let(:ec2_status) { 'pending' }
      it 'raises exception' do
        expect { subject.handle_message message }.to raise_error RuntimeError
      end
    end

    context "when instance's status is running" do
      let(:volumes) do
        [{ attachments: [{ volume_id: 'test', instance_id: instance_id, device: '/dev/sda1' }], volume_id: 'test' }]
      end
      let(:ec2_status) { 'running' }
      before(:each) do
        ec2_resource.client.stub_responses(:describe_volumes, volumes: volumes)
      end

      include_examples 'send message'

      it 'tags volumes' do
        expect(ec2_resource.client).to receive(:create_tags).and_wrap_original do |original, hash, &block|
          expect(hash[:resources]).to eq ['test']
          request_hash = hash[:tags].detect { |h| h[:key] == 'pantry_request_id' }
          expect(request_hash[:value]).to eq request_id.to_s
          original.call(hash, &block)
        end
        subject.handle_message message
      end

      it 'merges IP address with message for publishing' do
        subject.handle_message(message)
        expect(publisher).to have_received(:publish).with(hash_including(message))
        expect(publisher).to have_received(:publish).with(hash_including(ip_address: instance_ip, instance_id: instance_id))
      end
    end

    %w(shutting_down stopping stopped).each do |status|
      context "when instance's status is #{status}" do
        let(:ec2_status) { status }
        let(:ec2_status_regex) { Regexp.new(status.to_s) }

        it 'raises exception' do
          expect { subject.handle_message(message) }.to raise_exception RuntimeError
        end
      end
    end

    context 'when instance terminated' do
      let(:ec2_status) { 'terminated' }

      it 'publishes message to error topic' do
        subject.handle_message(message)
        expect(error_publisher).to have_received(:publish).with(message)
      end

      it 'does not publish message to topic' do
        subject.handle_message(message)
        expect(publisher).to_not have_received(:publish)
      end
    end
  end
end
