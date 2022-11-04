# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

require "puppet/type"
require "puppet/transaction"
require "json"

# Parse input.
input = JSON.parse(STDIN.read)
type = input.fetch("type")
attributes = input.fetch("attributes")

# Create resource.
resource = Puppet::Type::type(type).new(attributes)

# Evaluate resource.
transaction = Puppet::Transaction.new(Puppet::Resource::Catalog.new, nil, nil)
status = transaction.resource_harness.evaluate(resource)

if status.failed then 
    raise RuntimeError.new(status.events)
end

# Load properties with placeholder values if needed.
resource.class.properties.each do |property|
    resource.add_property_parameter(property.name) if !resource.property(property.name)
end

# Output resource.
puts resource.retrieve.parameters.to_json