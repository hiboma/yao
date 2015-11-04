module Yao::Resources
  class Tenant < Base
    friendly_attributes :id, :name, :description, :enabled

    self.service        = "identity"
    self.resource_name  = "tenant"
    self.resources_name = "tenants"
    self.admin          = true

    class << self
      def get_by_name(name)
        self.get("", name: name)
      end
      alias find_by_name get_by_name

      def accessible
        as_member { self.list }
      end
    end
  end
end
