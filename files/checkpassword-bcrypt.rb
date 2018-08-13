#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__), "checkpassword-bcrypt.incl.rb")

require 'rest_client'
require 'json'

CONF = {
  endpoint: 'https://immer12-8.glei.ch:9442',
  ca: '/etc/iapi/ca.crt',
  cert: '/etc/iapi/client.crt',
  key: '/etc/iapi/client.key',
}
CONF[:cert] = OpenSSL::X509::Certificate.new(File.read(CONF[:cert]))
CONF[:key] = OpenSSL::PKey::RSA.new(File.read(CONF[:key]))

def auth(user, userdb, pass, ip, untrusted_client)
  oldhome = ENV['HOME']
  Dir.mktmpdir do |temp|
    ENV['HOME'] = temp
    res = RestClient::Resource.new("#{CONF[:endpoint]}/auth/mailstore",
                                     :ssl_client_cert => CONF[:cert],
                                     :ssl_client_key  => CONF[:key],
                                     :ssl_ca_file     => CONF[:ca],
                                     :verify_ssl      => OpenSSL::SSL::VERIFY_PEER)
    query = {'email' => user, 'userdb' => userdb}
    if userdb
    else
      query['password'] = pass
      query['ip'] = ip
      query['unstrusted_client'] = untrusted_client
    end

    begin
      response = res.post(query.to_json)
    rescue RestClient::BadRequest => e
      err = JSON.parse(e.response)
      if err['errors'] == 'auth_fail'
        ENV['HOME'] = oldhome
        return false
      else
        warn "IAPI: Got unexpected rest error #{e}"
        ENV['HOME'] = oldhome
        return false
      end
    rescue => e
      warn "IAPI: Got unexpected error #{e}"
      ENV['HOME'] = oldhome
      return false
    end
    res = JSON.parse(response)
    ENV['HOME'] = oldhome
    if !res || res['result'] != "success"
      warn "IAPI: Got unexpected response #{res}"
      return false
    end
    res['login']
  end
end

def fix_encoding(str)
  # stupid dovecot gives us latin or utf-8 chars
  # we fix this by assuming all illegal utf-8 strings are in fact latin
  begin
    str.unpack("U*")
  rescue
    return Iconv.conv('utf-8', 'iso-8859-1', str)
  end
  str.force_encoding('UTF-8')
end

old_env = ENV.clone

#if authorized is set to 1, dovecot does a userdb lookup. no login required.
authorized = ENV['AUTHORIZED'].to_i
is_userdb = authorized == 1
dovecot = ARGV[0]
ip = ENV['TCPREMOTEIP']

begin
  input = IO.new(3,"r")
  (username,pass) = input.read.unpack("Z*Z*")
  input.close
rescue
  warn "could not read username/pass from stdin, terminating"
  exit InternalAuthError
end

def trusted_ip?(ip)
  Checkpassword::Config::TrustedIps.include?(ip)
end

untrusted_client = false
trusted_login = trusted_ip?(ip)
if trusted_login && pass =~ /(.*)##untrusted_login$/ then
  pass = $1
  trusted_login = false
end
if pass =~ /(.*)##untrusted_login$/ then
  untrusted_client = true
end

checker = Checkpassword::PasswordChecker.new

begin
  checker.prepare!

  # we do not want to fail on if we're just doing a userdb lookup
  fail_when_locked = (authorized != 1) && !trusted_login

  exit AuthError unless checker.user?(username, fail_when_locked)

  if authorized != 1
    exit AuthError unless checker.pass?(pass)
  end
rescue Checkpassword::InternalError
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
extras = []
extra_fields = is_userdb ? Checkpassword::Config::Dovecot::ExtraUserDBFields : Checkpassword::Config::Dovecot::ExtraPasswordDBFields
extra_fields.keys.each do |key|
  val = extra_fields[key]
  val = val.call(user) if val.is_a?(Proc)
  if val && (!val.respond_to?(:empty?) || !val.empty?)
    ENV[key] = val
    extras << key
  end
end
ENV['EXTRA']             = extras.join(' ')
ENV['AUTHORIZED']        = '2' if authorized == 1

p2 = fix_encoding(pass).force_encoding('UTF-8')
successful_login = auth(username, is_userdb, p2, ip, untrusted_client)
if !successful_login
  warn "IAPI login failed for #{user['name']}"
else
  successful_login.each do |k,v|
    if v && v != ""
      old_env[k] = v
    end
  end
  if (ENV.inspect != old_env.inspect)
    warn "Iapi sends wrong auth data.\nBcrypt check:\n#{ENV.inspect}\nIAPI:\n#{old_env.inspect}\n"
  end
end


# keep FD 4 open as dovecot communicates on that one
exec dovecot, { 4 => 4 }
