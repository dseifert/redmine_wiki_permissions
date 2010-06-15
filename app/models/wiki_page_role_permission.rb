class WikiPageRolePermission < ActiveRecord::Base
  belongs_to :wiki_page
  belongs_to :role
  
  validates_presence_of :role
  validates_presence_of :wiki_page

end
