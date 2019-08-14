class TestSecurityGroup < Test::Unit::TestCase
  def test_rule_attributes
    params = {
      "id" => "test_rule_id_1",
      "security_group_ip" => "test_group_id_1",
      "direction"         => "ingress",
      "protocol"          => "tcp",
      "ethertype"         => "IPv4",
      "port_range_max"    => "443",
      "port_range_min"    => "443",
      "remote_ip_prefix"  => "10.0.0.0/24",
      "remote_group_id"   => nil,
      "tenant_id"         => "test_tenant"
    }

    rule = Yao::SecurityGroupRule.new(params)
    assert_equal(rule.id, "test_rule_id_1")
    assert_equal(rule.protocol, "tcp")
    assert_equal(rule.port_range_max, "443")
    assert_equal(rule.port_range_min, "443")
    assert_equal(rule.ethertype, "IPv4")
  end

  sub_test_case 'port_range_max == port_range_min' do

    def test_port_and_port_range

      params = {
        "port_range_max"    => "443",
        "port_range_min"    => "443",
      }

      rule = Yao::SecurityGroupRule.new(params)
      assert_equal(rule.port, "443")
      assert_equal(rule.port_range, "443".."443")
    end
  end

  sub_test_case 'port_range_max > port_range_min' do

    def test_port_and_port_range

      params = {
        "port_range_max"    => "1024",
        "port_range_min"    => "512",
      }

      rule = Yao::SecurityGroupRule.new(params)
      assert_equal(rule.port, "1024".."512")
      assert_equal(rule.port_range, "1024".."512")
    end
  end

  def test_remote_ip_cidr

    params = {
      "remote_ip_prefix"  => "10.0.0.0/24",
    }

    rule = Yao::SecurityGroupRule.new(params)
    assert_equal(rule.remote_ip_cidr, "10.0.0.0/24")
  end
end
