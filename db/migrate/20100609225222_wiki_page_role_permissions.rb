class WikiPageRolePermissions < ActiveRecord::Migration
  def self.up
    create_table :wiki_page_role_permissions do |t|
      t.column :role_id, :integer
      t.column :wiki_page_id, :integer
      t.column :level, :integer
    end
  end

  def self.down
     drop_table :wiki_page_role_permissions
  end
end
