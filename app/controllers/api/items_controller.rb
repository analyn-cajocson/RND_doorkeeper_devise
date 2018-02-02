class Api::ItemsController < Api::BaseController
  before_action :doorkeeper_authorize! # equivalent of authenticate_user!

  def index
    @items = Item.all
    respond_with @items
  end

  # the rest of actions
end
