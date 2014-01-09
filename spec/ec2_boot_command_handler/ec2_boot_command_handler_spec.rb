require 'spec_helper'
require_relative "../../ec2_boot_command_handler/ec2_boot_command_handler"
require 'logger'

describe Wonga::Daemon::EC2BootCommandHandler do
  let(:ec2) { instance_double('AWS::EC2', instances: instances) }
  let(:instances) { instance_double('AWS::EC2::InstanceCollection', filter: [filtered_instance]) }
  let(:filtered_instance) { nil }
  let(:logger) { instance_double('Logger').as_null_object }
  let(:publisher) { instance_double('Wonga::Daemon::Publisher').as_null_object }
  let(:request_id) { 2 }
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

  subject { Wonga::Daemon::EC2BootCommandHandler.new(ec2, publisher, logger) }

  it_behaves_like "handler"

  describe "#handle_message" do
    context "when machine is not requested" do
      let(:attachments) { { 
        "/dev/sda1" => instance_double('AWS::EC2::Attachment', volume: volume),
        "/dev/sda2" => instance_double('AWS::EC2::Attachment', volume: volume)
        } 
      }              
      let(:created_instance) { instance_double('AWS::EC2::Instance', 
        tags:         tags,
        attachments:  attachments ) 
      }
      let(:tags)        { { 'pantry_request_id' => request_id.to_s } }    
      let(:vol_tags)    { {  } }    
      let(:volume)      { instance_double('AWS::EC2::Volume', tags: vol_tags) }
 
      before(:each) do
        instances.stub(:create).and_return(created_instance)
        tags.stub(:set)
        vol_tags.stub(:set)        
      end

      it "requests machine" do
        subject.handle_message(message) rescue nil
        expect(instances).to have_received(:create)
      end

      context "when no proxy attribute is provided" do
        it "requests machine with proxy" do
          expect(instances).to receive(:create).and_return(created_instance) do |args|
            expect(args[:user_data]).to include('PROXY')
          end
          subject.handle_message(message) rescue nil
        end
      end

      context "when proxy attribute is nil" do
        let(:message_nil_proxy) { message.merge({"http_proxy" => nil})  }
        it "requests machine with proxy" do
          expect(instances).to receive(:create).and_return(created_instance) do |args|
            expect(args[:user_data]).to include('PROXY')
          end
          subject.handle_message(message_nil_proxy) rescue nil
        end
      end

      context "when proxy attribute is provided" do
        let(:message_proxy)   { message.merge({"http_proxy" => "http://proxy.herp.derp:0"}) }
        it "requests machine with proxy" do
          instances.stub(:create).and_return(created_instance) do |args|
            expect(args[:user_data]).to include('PROXY')
          end
          subject.handle_message(message_proxy) rescue nil
        end
      end

      it "tags requested machine and volumes" do
        expect(tags).to receive(:set).with(hash_including('pantry_request_id' => request_id.to_s))
        expect(vol_tags).to receive(:set).with(hash_including(
          'Name' => "#{message["instance_name"]}.#{message["domain"]}_OS_VOL",
          'device' => "/dev/sda1"
          )
        )
        expect(vol_tags).to receive(:set).with(hash_including(
          'Name' => "#{message["instance_name"]}.#{message["domain"]}_VOL1",
          'device' => "/dev/sda2"
          )
        )          
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
        let(:tags) { {} }
        it "quits peacefully" do
          subject.handle_message(message)
        end
      end
    end
  end

  context "when machine is requested" do
    let(:instance_id) { "i-fake1337" }
    let(:instance_ip) { "192.168.13.37" }
    let(:filtered_instance) { instance_double('AWS::EC2::Instance', private_ip_address: instance_ip, id: instance_id, status: status) }

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
      let(:status) { :running }
      include_examples "send message"
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
