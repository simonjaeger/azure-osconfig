# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

require "chef/node" 
require "chef/event_dispatch/dispatcher" 
require "chef/run_context" 
require "chef/resources" 
require "chef/providers" 
require "chef/provider_resolver" 
require "chef/resource_resolver" 
require "json"

# Parse input.
input = JSON.parse(STDIN.read)
resource_class = input.fetch("resource_class")
resource_name = input.fetch("resource_name")

os = input["os"] || "linux"
platform = input["platform"] || "linux"
platform_family = input["platform_family"]
platform_version = input["platform_version"]
properties = input["properties"] || {}
action = input["action"] || :nothing # TODO: Use default.

# Create node with platform information used by resolvers. 
node = Chef::Node.new 
node.automatic[:os] = os
node.automatic[:platform] = platform
node.automatic[:platform_family] = platform_family
node.automatic[:platform_version] = platform_version

events = Chef::EventDispatch::Dispatcher.new 
run_context = Chef::RunContext.new(node, {}, events) 

# Resolve resource class and create resource. 
resource_class = Chef::ResourceResolver.resolve(resource_class, node: node) 
resource = resource_class.new(resource_name, run_context) 

# Configure resource.
properties.each do |key, value|
    resource.public_send(key, value)
end

# Run action. 
resource.run_action(action)

# Resolve provider class and create provider. 
provider_resolver = Chef::ProviderResolver.new(node, resource, :nothing) 
provider_class = provider_resolver.resolve() 
provider = provider_class.new(resource, run_context) 

# Load resource (previous may have been partial). 
resource = provider.load_current_resource() 

# Output resource. 
puts JSON.generate(resource) 