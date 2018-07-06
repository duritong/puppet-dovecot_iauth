# trees helper for authentication
class dovecot_iauth::trees {
  ensure_packages(['rubygem-ffi','libsodium'])
  file{
    '/usr/local/trees':
      ensure => directory,
      owner  => root,
      group  => 0,
      mode   => '0755';
    '/usr/local/trees/trees.rb':
      source  => 'puppet:///modules/dovecot_iauth/trees/trees.rb',
      owner   => root,
      group   => 0,
      mode    => '0644',
      require => Package['rubygem-ffi','libsodium'];
  }
}
