ActionController::Routing::Routes.draw do |map|
  map.connect 'projects/:project_id/importer/:action', :controller => 'importer'
end
