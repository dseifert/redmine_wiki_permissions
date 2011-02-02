ActionController::Routing::Routes.draw do |map|
  #  map.resources :projects do |project|
  #    project.resources :wiki, :except => [:new, :create], :member => {
  #      :rename => [:get, :post],
  #      :history => :get,
  #      :preview => :any,
  #      :protect => :post,
  #      :add_attachment => :post
  #    }, :collection => {
  #      :export => :get,
  #      :date_index => :get
  #    }
  #  end
  map.resources :projects, :member => {
    :copy => [:get, :post],
    :settings => :get,
    :modules => :post,
    :archive => :post,
    :unarchive => :post
  } do |project|
    project.resource :project_enumerations, :as => 'enumerations', :only => [:update, :destroy]
    project.resources :files, :only => [:index, :new, :create]
    project.resources :versions, :collection => {:close_completed => :put}, :member => {:status_by => :post}
    project.resources :news, :shallow => true
    project.resources :time_entries, :controller => 'timelog', :path_prefix => 'projects/:project_id'
    
    project.wiki_start_page 'wiki', :controller => 'wiki', :action => 'show', :conditions => {:method => :get}
    project.wiki_index 'wiki/index', :controller => 'wiki', :action => 'index', :conditions => {:method => :get}
    project.wiki_diff 'wiki/:id/diff/:version', :controller => 'wiki', :action => 'diff', :version => nil
    project.wiki_diff 'wiki/:id/diff/:version/vs/:version_from', :controller => 'wiki', :action => 'diff'
    project.wiki_annotate 'wiki/:id/annotate/:version', :controller => 'wiki', :action => 'annotate'
    project.resources :wiki, :except => [:new, :create], :member => {
      :rename => [:get, :post],
      :permissions => :get,
      :create_wiki_page_user_permissions => :post,
      :destroy_wiki_page_user_permissions => [:get, :post],
      :update_wiki_page_user_permissions => :post,
      :history => :get,
      :preview => :any,
      :protect => :post,
      :add_attachment => :post
    }, :collection => {
      :export => :get,
      :date_index => :get
    }
  end
  
  
end

