require_relative "../../ec2_boot_command_handler/ec2_boot_command_handler"
require 'spec_helper'

describe Daemons::EC2BootCommandHandler do
  let(:ec2) { AWS::EC2.new }
  let(:publisher) { instance_double('Publisher').as_null_object }
  let(:raise_msg) { {request_id: 1, instance_id: 2} }
  subject { Daemons::EC2BootCommandHandler.new(ec2, publisher) }
  let(:test_hash){ 
    {
      pantry_request_id: "",
      instance_name: "sqs test",
      flavor: "t1.micro",
      ami: "ami-fedfd48a",
      team_id: "test team",
      subnet_id: "subnet-f3c63a98", 
      security_group_ids: "sg-f94dc88e",
      aws_key_pair_name: 'eu-test-1'
    }
  }
  let(:good_msg){ test_hash.to_json }

  describe "#machine_already_booted" do
    it "Takes a non existing machine ID and returns false" do 
      expect(subject.machine_already_booted(-1)).to be false
    end
  end

  describe "#raise_machine_booted_event" do 
    it "Takes two ids and pokes SQS" do 
      subject.raise_machine_booted_event(test_hash, 2, "192.168.13.37")
      expect(publisher).to have_received(:publish)
    end
  end

  describe "#tag_and_wait_instance" do 
    it "Takes machine details and boots an ec2 instance" do 
      resp = ec2.client.stub_for(:describe_instance_status)
      resp.data[:instance_status_set] = [ {instance_status: {status: "ok"} } ]
      instance = double("instance", id: "i-1337")
      expect(
        subject.tag_and_wait_instance(instance, 1, "test_name", "test_team")
      ).not_to be_false
    end
  end
end
