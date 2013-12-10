require 'spec_helper'
require_relative "../../ec2_boot_command_handler/ec2_boot_command_handler"
require 'logger'

describe Wonga::Daemon::EC2BootCommandHandler do
  let(:logger) { instance_double('Logger').as_null_object }
  let(:publisher) { instance_double('Wonga::Daemon::Publisher').as_null_object }
  let(:instance_id) { 42 }
  let(:instance_ip) { "192.168.13.37" }
  let(:request_id) { 2 }
  let(:message) {
    {
      "pantry_request_id" => request_id,
      "instance_name" => "sqs test",
      "flavor" => "t1.micro",
      "ami" => "ami-fedfd48a",
      "team_id" => "test team",
      "subnet_id" => "subnet-f3c63a98",
      "security_group_ids" => ["sg-f94dc88e"],
      "aws_key_pair_name" => 'eu-test-1',
      "protected"         => false,
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
  let(:message_nil_proxy) { message.merge({"http_proxy" => nil})  }
  let(:message_proxy)     { message.merge({"http_proxy" => "http://proxy.herp.derp:0"}) }

  subject { Wonga::Daemon::EC2BootCommandHandler.new(publisher, logger) }

  it_behaves_like "handler"

  describe "#handle_message" do 
    context "machine not yet requested" do 
      it "requests a machine" do
        subject.stub(:find_machine_by_request_id).and_return(nil)
        subject.stub(:request_instance).and_return(nil)
        subject.stub(:tag_instance)
        subject.should receive(:tag_instance)
        expect{ 
          subject.handle_message(message) 
        }.to raise_error
      end
    end

    context "machine requested but not yet responding" do 
      let(:instance) { double(id: "i-fake1337") }      
      it "attempts to contact AWS and raises an error" do
        subject.stub(:find_machine_by_request_id).and_return(instance)
        expect{
          subject.handle_message(message)
        }.to raise_error
      end
    end

    context "machine responding and still initializing" do 
      let(:instance) { double(id: "i-fake1337") }      
      it "logs a pending message to syslog and raises an error" do
        subject.stub(:find_machine_by_request_id).and_return(instance)                
        resp = AWS::EC2.new.client.stub_for(:describe_instance_status)
        resp.data[:instance_status_set] = [ {instance_status: {status: "initializing"} } ]        
        expect(logger).to receive(:info)
        expect{
          subject.handle_message(message)
        }.to raise_error
      end
    end

    context "machine responding and in ok state" do 
      let(:instance) { 
        double(
          id: "i-fake1337",
          private_ip_address: "123.456.7.8"
        ) 
      }      
      it "logs a finished message, publishes and exists" do 
        subject.stub(:find_machine_by_request_id).and_return(instance)                
        resp = AWS::EC2.new.client.stub_for(:describe_instance_status)
        resp.data[:instance_status_set] = [ {instance_status: {status: "ok"} } ]        
        expect(publisher).to receive(:publish).with(message.merge(
          {
            instance_id: "i-fake1337", 
            instance_ip: "123.456.7.8"
          })
        )
        subject.handle_message(message)
      end
    end

    context "unexpected state" do 
      let(:instance) { double(id: "i-fake1337") }      
      it "logs an error" do 
        subject.stub(:find_machine_by_request_id).and_return(instance)                
        resp = AWS::EC2.new.client.stub_for(:describe_instance_status)
        resp.data[:instance_status_set] = [ {instance_status: {status: "D34DB33F"} } ]        
        expect(logger).to receive(:error)      
        subject.handle_message(message)        
      end
    end
  end

  describe "#request_instance" do   
    let(:instance) { double(instance_id: "i-fake1337") }

    it "calls AWS to create an instance" do 
      client = AWS::EC2.new.client
      resp = client.stub_for(:run_instances)
      resp[:instances_set] << instance
      expect(
        subject.request_instance(message)
      ).to be_kind_of AWS::EC2::Instance
    end
  end      

  describe "#render_user_data" do
    context "no proxy field" do
      it "renders userdata without proxy variables" do
        expect(subject.render_user_data(message)).not_to include("PROXY")
      end
    end
    context "nil proxy field" do
      it "renders userdata without proxy variables" do
        expect(subject.render_user_data(message_nil_proxy)).not_to include("PROXY")
      end
    end
    context "proxy field specified" do
      it "renders userdata with proxy variables" do
        expect(subject.render_user_data(message_proxy)).to include("PROXY")
      end
    end
  end

  describe "#find_machine_by_request_id" do
    it "returns nil for a non existing machine ID" do
      expect(subject.find_machine_by_request_id(-1)).to be_nil
    end

    it "returns machine if it can be found" do
      client = AWS::EC2.new.client
      resp = client.stub_for(:describe_instances)
      resp[:reservation_set] << double(instances_set: [double(:instance_id => 'test')])
      expect(subject.find_machine_by_request_id(-1).id).to be_eql('test')

      # stub_for stay after test run
      client.instance_variable_set(:@stubs, {})
    end
  end

  describe "#device_hash_keys_to_symbols" do 
    let (:string_hash) { 
      { "key1" => "val1",
        "key2" => { "nestedKey" => "nestedVal" }
      }
    }
    let (:symbol_hash) {
      { key1: "val1",
        key2: { nestedKey: "nestedVal" }
      }
    }
    it "takes a string indexed hash and returns a symbol indexed hash" do 
      expect(subject.device_hash_keys_to_symbols(string_hash)).to be_eql(symbol_hash)
    end
  end
end