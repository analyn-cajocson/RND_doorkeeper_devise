class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  def self.authenticate(email, password)
    user = User.find_for_authentication(email: email)
    user.try(:valid_password?, password) ? user : nil
    revoke_token(user)
    user
  end

  def self.revoke_token(user)
    if user
      sessions = OauthAccessToken.where(resource_owner_id: user.id)
      sessions.each do |s|
        s.revoked_at = DateTime.now
        s.save
      end
    end
  end
end
