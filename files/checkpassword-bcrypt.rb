#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__), "checkpassword-bcrypt.incl.rb")

#if authorized is set to 1, dovecot does a userdb lookup. no login required.
authorized = ENV['AUTHORIZED'].to_i
dovecot = ARGV[0]

begin
  input = IO.new(3,"r")
  (username,pass) = input.read.unpack("Z*Z*")
  input.close
rescue
  warn "could not read username/pass from stdin, terminating"
  exit InternalAuthError
end

checker = CheckpasswordBCrypt::PasswordChecker.new

begin
  checker.prepare!

  # we do not want to fail on if we're just doing a userdb lookup
  exit AuthError unless checker.user?(username, (authorized != 1))

  if authorized != 1
    exit AuthError unless checker.pass?(pass)
  end
rescue CheckpasswordBCrypt::InternalError
  warn "authentication not possible, terminating..."
  exit InternalAuthError
end

user = checker.user
# do not perform a full login if dovecot just does a userdb lookup
checker.login! unless authorized == 1

# cleanup checker
checker.finish

ENV['USER']              = user['name']
ENV['HOME']              = File.join(user['home'],user['name'])
ENV['userdb_quota_rule'] = user['quota']
ENV['userdb_uid']        = user['uid']
ENV['userdb_gid']        = user['gid']
ENV['EXTRA']             = 'userdb_uid userdb_gid userdb_quota_rule'
ENV['AUTHORIZED']        = '2' if authorized == 1
# keep FD 4 open as dovecot communicates on that one
exec dovecot, { 4 => 4 }
