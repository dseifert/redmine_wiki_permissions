module WikiPermissions
  module MixinSearchController
    def self.included base
      base.class_eval do
        alias_method :_index, :index unless method_defined? :_index

        def index
          _index
          
          if @results != nil
            @results.delete_if do |result|
              result.class == WikiPage and
              not User.current.can_view? result
            end
          end
        end
        
      end      
    end
  end
  module MixinWikiPage
    def self.included base
      
      base.class_eval do
        has_many :user_permissions, :class_name => 'WikiPageUserPermission'
        has_many :role_permissions, :class_name => 'WikiPageRolePermission'
        after_create :role_creator
      end
      
      def leveled_permissions level
        WikiPageUserPermission.all :conditions => { :wiki_page_id => id, :level => level }
      end
      
      def default_permission
        WikiPageUserPermission.first :conditions => { :wiki_page_id => id, :member_id => nil }
      end

      def users_by_level level
        users = Array.new
        leveled_permissions(level).each do |permission|
          users << permission.user if permission.member_id
        end
        users
      end

      def users_without_permissions
        project.users - users_with_permissions
      end
      
      def users_with_permissions
        users = Array.new
        WikiPageUserPermission.all(:conditions => { :wiki_page_id => id }).each do |permission|
          users << permission.user if permission.member
        end
        users        
      end
      
      def members_without_permissions
        project.members - members_with_permissions
      end
      
      def members_with_permissions
        members_wp = Array.new
        user_permissions.each do |permission|
          members_wp << permission.member if permission.member_id
        end
        members_wp
      end
      
      def roles_without_permissions
        #Rails.logger.info "Start Roles"
        givable_roles = Role.find_all_givable
        permissed_roles = roles_with_permissions
        my_roles = Array.new
        #Rails.logger.info "Iterate"
        givable_roles.each do |givable_role|
          role_found = false
          #Rails.logger.info "Iterate on: #{givable_role.name}"
          permissed_roles.each do |permissed_role|
            #Rails.logger.info "Permissed_role: #{permissed_role.name}"
            #Rails.logger.info "PRole ID: #{permissed_role.id}"
            #Rails.logger.info "Role: #{givable_role.id}"
            if permissed_role.id == givable_role.id
              #Rails.logger.info "Role found"
              role_found = true
              break
            end
            #Rails.logger.info "Role not found"
          end
          #Rails.logger.info "Adding: #{role_found}"
          my_roles << givable_role unless role_found
        end
        #Rails.logger.info "End Roles"
        return my_roles
      end
      
      def roles_with_permissions
        roles_wp = Array.new
        role_permissions.each do |permission|
          roles_wp << permission.role
          #Rails.logger.info "#{permission.role}"
        end
        return roles_wp
      end
      private      
      
      def role_creator
        member = self.wiki.project.members.find_by_user_id(User.current.id)
        WikiPageUserPermission.create(:wiki_page_id => id, :level => 3, :member_id => member.id) unless member.nil?
      end
    end
  end
  
  module MixinMember
    def self.included base
      base.class_eval do
        has_many :wiki_page_user_permissions
      end
    end
  end
  
  
  
  module MixinUser
    def self.included base
      base.class_eval do
            
        alias_method :_allowed_to?, :allowed_to? unless method_defined? :_allowed_to?
        
        def not_has_permission? page
          admin or
          WikiPageUserPermission.first(
            :conditions => {
              :wiki_page_id => page.id,
              :member_id => nil
            }
          ) == nil or
          WikiPageUserPermission.first(
            :conditions => {
              :wiki_page_id => page.id,
              :member_id => Member.first(:conditions => { :user_id => id, :project_id => page.project.id }).id
            }
          ) == nil
        end

        # checks the permission level of the user
        #  - if the user has an explicit permission level, use this one
        #  - if a user's role has an explicit permission level, use this one
        #  - if a default permission is set for the page, use it
        #  - if no permissions are set at all, allow access

        def user_permission_greater? page, level          
          return true if admin
 
          # access for non-members is not permitted
          as_member = Member.first(:conditions => { :user_id => id, :project_id => page.project.id })
          return false if as_member.nil?

          # user specific permissions have preference
          #Rails.logger.info "Accessing user permission for user #{id} / member #{as_member.id} and page #{page.id}"
          user_permission = WikiPageUserPermission.first(
            :conditions => {
              :wiki_page_id => page.id,
              :member_id => as_member.id
            }
          )

          unless user_permission.nil?
            Rails.logger.info "Level: #{user_permission.level} => #{level}"
            return user_permission.level >= level
          end
          
          # check whether the user belongs to a role that has permissions set
          role_permissions = WikiPageRolePermission.find(:all, :conditions => {:wiki_page_id => page.id})
          unless role_permissions.nil? or as_member.roles.empty?
            roles_ids = as_member.roles.map { |x| x.id }
            Rails.logger.info "Accessing role permission"
          
            role_permissions.each do |role|
              if roles_ids.index(role.role_id)
                Rails.logger.info "Role.level #{role.level} >= #{level}"
                return role.level >= level
              end
            end
          end

          # check default permission
          Rails.logger.info "Checking default"
          (default = page.default_permission) ? default.level >= level : true
        end
        
        def can_edit? page
          user_permission_greater? page, 2
        end
                
        def can_edit_permissions? page
          user_permission_greater? page, 3
        end
        
        def can_view? page
          user_permission_greater? page, 1
        end

        def allowed_to?(action, project, options={})
          # first check the actual permissions
          original_permissions = _allowed_to?(action, project, options)

          # if original permissions are false then we can't override them (as user won't have
          # seen the Wiki tab in the first place so we don't bother)
          return original_permissions if !original_permissions
          
          # we require a project (fixes http://www.redmine.org/issues/8560)
          return original_permissions unless (project && project.is_a?(Project))
            
          # also use the original permissions if this plugin is not even running
          return original_permissions unless (\
            project.enabled_modules.detect { |enabled_module| enabled_module.name == 'wiki_permissions' } != nil and \
            action.class == Hash and \
            action[:controller] == 'wiki')
          
          # now apply our own permissions. we need to re-check everything that grants permission
            
          # root may do anything
          return true if User.current and User.current.admin

          if [
                  'index',
                  'history',
                  'edit',
                  'permissions',                
                  'show',
                  'create_wiki_page_user_permissions',
                  'create_wiki_page_role_permissions',
                  'update_wiki_page_permissions',
                  'destroy_wiki_page_permissions'
            ].include? action[:action] and
            options.size != 0   

            Rails.logger.info("checking permissions, action #{action[:action]}, title #{options[:params][:id]}")

            wiki_page = WikiPage.first(:conditions => { :wiki_id => project.wiki.id, :title => options[:params][:id] })
            unless wiki_page.nil?
                return case action[:action]
                  when 'index'
                    can_view? wiki_page
                  when 'show'
                    can_view? wiki_page
                  when 'history'
                    can_view? wiki_page
                  when 'edit'
                    can_edit? wiki_page
                  else
                    can_edit_permissions? wiki_page
                end
            end
            
            return false
          else
            return original_permissions
          end
        end
      end
    end
  end
  
  module MixinWikiController
    def self.included base
      base.class_eval do
        
        helper_method :include_module_wiki_permissions?
        
        alias_method :_index, :index unless method_defined? :_index
        
        def index
          _index
        end

        def authorize ctrl = params[:controller], action = params[:action]
          allowed = User.current.allowed_to?({ :controller => ctrl, :action => action }, @project, { :params => params })
          allowed ? true : deny_access
        end
        
        def permissions
          find_existing_page
          @wiki_page_user_permissions = WikiPageUserPermission.all :conditions => ["wiki_page_id = ? AND member_id is not null", @page.id]
          @wiki_page_role_permissions = WikiPageRolePermission.all :conditions => { :wiki_page_id => @page.id }
          render :template => 'wiki/edit_permissions'
        end
        
        def create_wiki_page_user_permissions
          @wiki_page_user_permission = WikiPageUserPermission.new(params[:wiki_permission])
          if @wiki_page_user_permission.save
            redirect_to :action => 'permissions'
          else
            redirect_to :action => 'permissions'
          end
        end
        
        def create_wiki_page_role_permissions
          @wiki_page_role_permission = WikiPageRolePermission.new(params[:wiki_permission])
          if @wiki_page_role_permission.save
            redirect_to :action => 'permissions'
          else
            redirect_to :action => 'permissions'
          end
        end
        
        def update_wiki_page_permissions
          is_user = params[:wiki_page_permission][:permission_type].to_i == 0
          params[:wiki_permission].each_pair do |index, level|
            permission = nil
            if is_user
              permission = WikiPageUserPermission.find(index.to_i)
            else
              permission = WikiPageRolePermission.find(index.to_i)
              Rails.logger.info("Permissions: #{permission}")
            end
            permission.level = level.to_i
            Rails.logger.info("Level: #{permission.level.to_s} for #{index}/#{is_user}")
            permission.save
          end
          redirect_to :back
        end
        
        def destroy_wiki_page_permissions
          is_user = params[:permission_type].to_i == 0
          permission_id = params[:permission_id].to_i
          permission = nil
          if is_user
              permission = WikiPageUserPermission.find(permission_id)
            else
              permission = WikiPageRolePermission.find(permission_id)
          end
          permission.destroy
          
        	redirect_to :back
       end
        
        def include_module_wiki_permissions?
          (@page.project.enabled_modules.detect { |enabled_module| enabled_module.name == 'wiki_permissions' }) != nil
        end
        
      end
    end
  end  
end

require 'dispatcher'
  Dispatcher.to_prepare do 
    begin
      require_dependency 'application'
    rescue LoadError
      require_dependency 'application_controller'
    end

  Member.send :include, WikiPermissions::MixinMember
  WikiPage.send :include, WikiPermissions::MixinWikiPage  
  WikiController.send :include, WikiPermissions::MixinWikiController
  SearchController.send :include, WikiPermissions::MixinSearchController
  User.send :include, WikiPermissions::MixinUser
end