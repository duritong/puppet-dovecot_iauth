class dovecot-iauth::base {
    require rubygems::postgres

    package { 'dovecot-iauth':
        ensure => present,
    }
}
