class dovecot-iauth::base {
    package { 'dovecot-iauth':
        ensure => present,
    }
}