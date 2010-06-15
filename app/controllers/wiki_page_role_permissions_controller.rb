class WikiPageUserPermissionsController < ApplicationController
  

  def destroy
    WikiPageRolePermission.find(params[:id]).destroy
    redirect_to :back
  end
  
  def update
    params[:wiki_page_role_permission].each_pair do |index, level|
      permission = WikiPageRolePermission.find index.to_i
      permission.level = level.to_i
      permission.save
    end
    redirect_to :back
  end
end