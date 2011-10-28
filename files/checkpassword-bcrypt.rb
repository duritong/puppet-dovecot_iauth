#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__), "checkpassword-bcrypt.incl.rb")

#if authorized is set to 1, dovecot does a userdb lookup. no login required.
authorized = ENV['AUTHORIZED']
dovecot = ARGV[0]

begin
  input = IO.new(3,"r")
  (username,pass) = input.read.unpack("Z*Z*")
  input.close
rescue
  exit AuthError
end

checker = CheckpasswordBCrypt::PasswordChecker.new

user = checker.get_user(username)
exit AuthError if user.nil? || user.empty?

if( authorized != "1" )
  exit AuthError unless checker.hash?(user, pass)
  checker.login( user )
end

new_env = "USER='#{user[:name]}' "+
          "HOME='#{user[:home]}#{user[:name]}' "+
          "EXTRA=\"userdb_uid userdb_gid userdb_quota_rule\" "+
          "userdb_quota_rule='#{user[:quota]}' "+
          "userdb_uid='#{user[:uid]}' "+
          "userdb_gid='#{user[:gid]}' "+
          (authorized == "1" ? "AUTHORIZED=2" : '')

exec "#{new_env} #{dovecot}"

