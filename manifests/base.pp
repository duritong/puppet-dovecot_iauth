class dovecot-iauth::base {
    require rubygems::active_support
    require rubygems::postgres
    require rubygems::digest

    package { 'dovecot-iauth':
        ensure => present,
    }
}
