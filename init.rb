require 'redmine'

Redmine::Plugin.register :redmine_importer do
  name 'Issue Importer'
  author 'Martin Liu / Leo Hourvitz / Stoyan Zhekov / Akiko Takano / y.yoshida'
  description 'Issue import plugin for Redmine.'
  version '1.2.1'
  url 'https://github.com/yoshidayo/redmine_importer'
  author_url 'http://www.ibs.inte.co.jp/'

  project_module :importer do
    permission :import, :importer => :index
  end
  menu :project_menu, :importer, { :controller => 'importer', :action => 'index' }, :caption => :label_import, :before => :settings, :param => :project_id
end
