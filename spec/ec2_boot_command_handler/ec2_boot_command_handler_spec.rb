require 'spec_helper'
require_relative "../../ec2_boot_command_handler/ec2_boot_command_handler"
require 'logger'

describe Wonga::Daemon::EC2BootCommandHandler do
  let(:ec2) { instance_double('AWS::EC2', instances: instances) }
  let(:instances) { instance_double('AWS::EC2::InstanceCollection', filter: [filtered_instance]) }
  let(:filtered_instance) { nil }
  let(:logger) { instance_double('Logger').as_null_object }
  let(:publisher) { instance_double('Wonga::Daemon::Publisher', publish: message) }
  let(:request_id) { 2 }
  let(:retry_count) { 0 }
  let(:message) {
    {
      "pantry_request_id" => request_id,
      "instance_name" => "sqs test",
      "domain" => "blop.hurr",
      "flavor" => "t1.micro",
      "ami" => "ami-fedfd48a",
      "team_id" => "test team",
      "subnet_id" => "subnet-f3c63a98",
      "security_group_ids" => ["sg-f94dc88e"],
      "aws_key_pair_name" => 'eu-test-1',
      "platform"     => "windows",
      "protected"     => false,
      "block_device_mappings" =>
      [
        { virtual_name: "some string",
          device_name: "some string",
          ebs: {
            snapshot_id: "some ide"
          }
      }
      ]
    }
  }

  subject { Wonga::Daemon::EC2BootCommandHandler.new(ec2, {'retries' => retry_count}, publisher, logger) }

  it_behaves_like "handler"

  describe "#handle_message" do
    context "when machine is not requested" do
      let(:created_instance) { instance_double('AWS::EC2::Instance', tags: tags) }
      let(:tags)        { { 'pantry_request_id' => request_id.to_s } }

      before(:each) do
        instances.stub(:create).and_return(created_instance)
        tags.stub(:set)
      end

      it "requests machine" do
        subject.handle_message(message) rescue nil
        expect(instances).to have_received(:create)
      end

      context "when no proxy attribute is provided" do
        it "requests machine with proxy" do
          expect(instances).to receive(:create) do |args|
            expect(args[:user_data]).not_to include('PROXY')
            created_instance
          end
          subject.handle_message(message) rescue nil
        end
      end

      context "when proxy attribute is provided" do
        let(:message_proxy)   { message.merge({"http_proxy" => "http://proxy.herp.derp:0"}) }
        it "requests machine with proxy" do
          instances.stub(:create) do |args|
            expect(args[:user_data]).to include('PROXY')
            created_instance
          end
          subject.handle_message(message_proxy) rescue nil
        end
      end

      context "when Linux platform specified" do
        let(:message_linux)   { message.merge({"platform" => "linux"}) }
        it "requests machine with proxy" do
          instances.stub(:create) do |args|
            expect(args[:user_data]).to include("#{message["instance_name"]}.#{message["domain"]}")
            expect(args[:user_data]).to include("hostname #{message["instance_name"]}")
            created_instance
          end
          subject.handle_message(message_proxy) rescue nil
        end
      end

      it "tags requested machine" do
        expect(tags).to receive(:set).with(hash_including('pantry_request_id' => request_id.to_s))
        subject.handle_message(message) rescue nil
      end

      it "raise exception after tagging" do
        expect { subject.handle_message(message) }.to raise_error
      end


      context "when machine can't be requested" do
        it "raise exception" do
          instances.stub(:create).and_raise
          expect {
            subject.handle_message(message) 
          }.to raise_error
        end
      end

      context "when machine wasn't tagged" do
        context "because of exception" do
          let(:retry_count) { 10 }
          it "quits peacefully after trying to set tags several times" do
            allow(subject).to receive(:sleep)
            expect(tags).to receive(:set).with(hash_including('pantry_request_id' => request_id.to_s)).and_raise.exactly(retry_count).times
            subject.handle_message(message)
          end
        end
      end
    end
  end

  context "when machine is requested" do
    let(:instance_id) { "i-fake1337" }
    let(:instance_ip) { "192.168.13.37" }
    let(:filtered_instance) { instance_double('AWS::EC2::Instance', status: status) }

    context "when machine can't return current status" do
      let(:status) { nil }
      it "raise exception and log error" do
        expect{
          subject.handle_message
        }.to raise_error
      end
    end


    context "when machine's status is pending" do
      let(:status) { :pending }
      it "raise exception" do
        expect{
          subject.handle_message(message)
        }.to raise_error
      end
    end

    context "when machine's status is running" do
      let(:attachments) { {
        "/dev/sda1" => instance_double('AWS::EC2::Attachment', volume: volume),
        "/dev/sda2" => instance_double('AWS::EC2::Attachment', volume: volume)
      }
      }

      let(:filtered_instance) {
        instance_double('AWS::EC2::Instance',
                        private_ip_address: instance_ip,
                        id: instance_id,
                        status: :running,
                        attachments: attachments)
      }
      let(:merged_message) { message.merge({instance_id: instance_id, ip_address: instance_ip, private_ip: instance_ip})}
      let(:vol_tags)    { instance_double('AWS::EC2::ResourceTagCollection', set: true) }
      let(:volume)      { instance_double('AWS::EC2::Volume', tags: vol_tags) }

      include_examples "send message"

      it "tags volumes" do
        expect(vol_tags).to receive(:set).with(hash_including(
          'Name' => "#{message["instance_name"]}.#{message["domain"]}_OS_VOL",
          'device' => "/dev/sda1"
        )
                                              )
        expect(vol_tags).to receive(:set).with(hash_including(
          'Name' => "#{message["instance_name"]}.#{message["domain"]}_VOL1",
          'device' => "/dev/sda2"
        ))
        subject.handle_message(message)
      end

      it "merges IP address with message for publishing" do
        subject.handle_message(message)
        expect(publisher).to have_received(:publish).with(merged_message)
      end
    end

    [:shutting_down, :terminated, :stopping, :stopped].each do |state|
      context "when machine's status is #{state}" do
        let(:status) { state }
        it "quits peacefully" do
          subject.handle_message(message)
        end
      end
    end
  end
end
