require 'redmine'
require 'diff'
require 'rubygems'
require File.dirname(__FILE__) + '/lib/wiki_permissions.rb'

# This plugin should be reloaded in development mode.
if RAILS_ENV == 'development'
  ActiveSupport::Dependencies.load_once_paths.reject!{|x| x =~ /^#{Regexp.escape(File.dirname(__FILE__))}/}
end

Redmine::Plugin.register :redmine_wiki_permissions do
  name 'Redmine Wiki Permissions plugin'
  author 'Edward Tsech, David Pitman, Daniel Seifert, et al'
  description 'This redmine plugin adds permissions for every wiki page'
  version '1.1'
  
  project_module "wiki_permissions" do
    permission :edit_wiki_permissions, { :wiki => :permissions }
  end
end
