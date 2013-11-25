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
      "protected"         => false
    }
  }

  subject { Wonga::Daemon::EC2BootCommandHandler.new(publisher, logger) }

  it_behaves_like "handler"

  describe "#handle_message" do
    let(:instance) { double(id: instance_id, private_ip_address: instance_ip) }

    before(:each) do
      subject.stub(:boot_machine).and_return(instance)
    end

    include_examples "send message"

    context "when machine is already booted" do
      before(:each) do
        subject.stub(:find_machine_by_request_id).with(request_id).and_return(instance)
      end

      include_examples "send message"
    end
  end

  describe "#create_instance" do   
    let(:instance) { double(instance_id: "i-fake1337") }

    it "calls AWS to create an instance" do 
      client = AWS::EC2.new.client
      resp = client.stub_for(:run_instances)
      resp[:instances_set] << instance
      expect(subject.create_instance(
        "ami", 
        "flavor", 
        "secgroup_ids", 
        "subnet_id", 
        "key_name", 
        [
          { virtual_name: "some string",
            device_name: "some string",
            ebs: {
              snapshot_id: "some ide"
            }
          }
        ], 
        false,
        "user_data")
      ).to be_kind_of AWS::EC2::Instance
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

  describe "#raise_machine_booted_event" do
    it "takes two ids and pokes SQS" do
      publisher.stub(:publish) do |hash|
        expect(hash[:instance_id]).to eql(instance_id)
      end

      subject.raise_machine_booted_event(message, instance_id, instance_ip)
    end
  end

  describe "#tag_and_wait_instance" do
    it "Takes machine details and boots an ec2 instance" do 
      resp = AWS::EC2.new.client.stub_for(:describe_instance_status)
      resp.data[:instance_status_set] = [ {instance_status: {status: "ok"} } ]
      instance = double("instance", id: "i-1337")
      expect(
        subject.tag_and_wait_instance(instance, 1, "test_name", "test_domain", "test_team")
      ).not_to be_false
    end
  end
end
