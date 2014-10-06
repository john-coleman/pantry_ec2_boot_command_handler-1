require 'spec_helper'
require 'logger'
require_relative '../../../../lib/wonga/pantry/ec2_boot_command_handler'

describe Wonga::Pantry::EC2BootCommandHandler do
  let(:ec2) { instance_double('AWS::EC2', instances: instances) }
  let(:instances) { instance_double('AWS::EC2::InstanceCollection', filter: [ filtered_instance ]) }
  let(:instance_id) { 'i-fake1337' }
  let(:filtered_instance) { nil }
  let(:logger) { instance_double('Logger').as_null_object }
  let(:publisher) { instance_double('Wonga::Daemon::Publisher', publish: message) }
  let(:request_id) { 2 }
  let(:retry_count) { 0 }
  let(:config) {
    {
      'retries' => retry_count,
      'shutdown_schedule' => 'bluemoon'
    }
  }
  let(:message) {
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
      'domain' => 'blop.hurr',
      'flavor' => 't1.micro',
      'instance_name' => 'sqs-test',
      'pantry_request_id' => request_id,
      'platform' => 'windows',
      'protected' => false,
      'security_group_ids' => ['sg-f94dc88e'],
      'subnet_id' => 'subnet-f3c63a98',
      'team_id' => 'test team',
    }
  }

  subject {described_class.new(ec2, config, publisher, logger) }

  it_behaves_like 'handler'

  describe '#handle_message' do
    context 'when instance does not already exist' do
      let(:created_instance) { instance_double('AWS::EC2::Instance', tags: tags, id: instance_id) }
      let(:tags)        { { 'pantry_request_id' => request_id.to_s } }

      before(:each) do
        allow(instances).to receive(:create).and_return(created_instance)
        tags.stub(:set)
        allow(logger).to receive(:info).with(kind_of(String))
        allow(logger).to receive(:error).with(kind_of(String))
      end

      it 'requests instance' do
        expect(instances).to receive(:create)
        expect(logger).to receive(:info).with(/requested/)
        expect { subject.handle_message(message) }.to raise_exception
      end

      context 'when no proxy attribute is provided' do
        it 'requests instance without proxy' do
          expect(instances).to receive(:create) do |args|
            expect(args[:user_data]).not_to include('SETX HTTP_PROXY')
            created_instance
          end
          expect(logger).to receive(:info).with(/requested/)
          expect { subject.handle_message(message) }.to raise_exception
        end
      end

      context 'when proxy attribute is provided' do
        let(:message_proxy) { message.merge({'http_proxy' => 'http://proxy.herp.derp:0'}) }

        it 'requests instance with proxy' do
          instances.stub(:create) do |args|
            expect(args[:user_data]).to include('SETX HTTP_PROXY')
            created_instance
          end
          expect(logger).to receive(:info).with(/requested/)
          expect { subject.handle_message(message_proxy) }.to raise_exception
        end
      end

      context 'when Linux platform specified' do
        let(:message_linux)   { message.merge({'platform' => 'linux'}) }
        it 'requests instance with hostname set in user_data' do
          instances.stub(:create) do |args|
            expect(args[:user_data]).to include("#{message['instance_name']}.#{message['domain']}")
            expect(args[:user_data]).to include("hostname #{message['instance_name']}")
            created_instance
          end
          expect(logger).to receive(:info).with(/requested/)
          expect { subject.handle_message(message_linux) }.to raise_exception
        end
      end

      context 'when shutdown schedule specified' do
        let(:message_shutdown) { message.merge({'shutdown_schedule' => 'sometimes'}) }
        it 'tags requested instance, logs info and raises exception' do
          expect(logger).to receive(:info).with(/requested/).ordered
          expect(tags).to receive(:set).with(hash_including(
            'Name' => "#{message['instance_name']}.#{message['domain']}",
            'pantry_request_id' => request_id.to_s,
            'shutdown_schedule' => message_shutdown['shutdown_schedule'],
            'team_id'           => message_shutdown['team_id'].to_s
          )).ordered
          expect(logger).to receive(:info).with(/tagged/).ordered
          expect { subject.handle_message(message_shutdown) }.to raise_exception
        end
      end

      context 'when no shutdown schedule specified' do
        it 'tags requested instance, logs info and raises exception' do
          expect(logger).to receive(:info).with(/requested/).ordered
          expect(tags).to receive(:set).with(hash_including(
            'Name' => "#{message['instance_name']}.#{message['domain']}",
            'pantry_request_id' => request_id.to_s,
            'shutdown_schedule' => config['shutdown_schedule'],
            'team_id'           => message['team_id'].to_s
          )).ordered
          expect(logger).to receive(:info).with(/tagged/).ordered
          expect { subject.handle_message(message) }.to raise_exception
        end
      end

      context "when instance can't be requested" do
        it 'raise exception' do
          instances.stub(:create).and_raise
          expect { subject.handle_message(message) }.to raise_exception
        end
      end

      context 'when instance not tagged' do
        let(:retry_count) { 10 }

        it 'retries before raising exception' do
          allow(subject).to receive(:sleep)
          expect(tags).to receive(:set).with(hash_including('pantry_request_id' => request_id.to_s)).and_raise.exactly(retry_count).times
          expect { subject.handle_message(message) }.to raise_exception
        end
      end
    end
  end

  context 'when instance is requested' do
    let(:instance_ip) { '192.168.13.37' }
    let(:filtered_instance) { instance_double('AWS::EC2::Instance', status: ec2_status, id: instance_id) }

    context "when instance can't return current status" do
      let(:ec2_status) { nil }
      it 'logs error and raises exception' do
        expect(logger).to receive(:error).with(/unexpected state/)
        expect{ subject.handle_message(message) }.to raise_exception
      end
    end

    context "when instance's status is pending" do
      let(:ec2_status) { :pending }
      it 'logs info raises exception' do
        expect(logger).to receive(:info).with(/pending/)
        expect{ subject.handle_message(message) }.to raise_exception
      end
    end

    context "when instance's status is running" do
      let(:attachments) { {
        '/dev/sda1' => instance_double('AWS::EC2::Attachment', volume: volume),
        '/dev/sda2' => instance_double('AWS::EC2::Attachment', volume: volume)
      } }
      let(:filtered_instance) {
        instance_double('AWS::EC2::Instance',
                        private_ip_address: instance_ip,
                        id: instance_id,
                        status: :running,
                        attachments: attachments)
      }
      let(:merged_message) {
        message.merge({instance_id: instance_id,
                       ip_address: instance_ip,
                       private_ip: instance_ip})
      }
      let(:vol_tags)    { instance_double('AWS::EC2::ResourceTagCollection', set: true) }
      let(:volume)      { instance_double('AWS::EC2::Volume', tags: vol_tags) }

      include_examples 'send message'

      it 'tags volumes' do
        expect(vol_tags).to receive(:set).with(hash_including(
          'Name' => "#{message['instance_name']}.#{message['domain']}_OS_VOL",
          'device' => '/dev/sda1'
        ) )
        expect(vol_tags).to receive(:set).with(hash_including(
          'Name' => "#{message['instance_name']}.#{message['domain']}_VOL1",
          'device' => '/dev/sda2'
        ) )
        subject.handle_message(message)
      end

      it 'merges IP address with message for publishing' do
        expect(logger).to receive(:info).with(/volumes tagged, publishing event/)
        subject.handle_message(message)
        expect(publisher).to have_received(:publish).with(merged_message)
      end
    end

    [ :shutting_down, :terminated, :stopping, :stopped ].each do |status|
      context "when instance's status is #{status.to_s}" do
        let(:ec2_status) { status }
        let(:ec2_status_regex) { Regexp.new(status.to_s) }

        before(:each) do
          allow(logger).to receive(:error).with(ec2_status_regex)
        end

        it 'logs error and raises exception' do
          expect(logger).to receive(:error).with(ec2_status_regex)
          expect { subject.handle_message(message) }.to raise_exception
        end
      end
    end
  end
end
