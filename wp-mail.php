<?php
/**
 * Fetches posts sent via email.
 *
 * @package WordPress
 */

define( 'WP_USE_THEMES', false );
require __DIR__ . '/wp-load.php';

if ( ! isset( $pop3 ) ) {
	require_once ABSPATH . WPINC . '/class-pop3.php';
}

$time_diff = get_option( 'gmt_offset' ) * HOUR_IN_SECONDS;
$pop3 = new POP3();

$hostname = get_option( 'mailserver_url' );
$username = get_option( 'mailserver_login' );
$password = get_option( 'mailserver_pass' );
$port     = get_option( 'mailserver_port' );

if ( empty( $hostname ) || empty( $username ) || empty( $password ) ) {
	wp_die( "This feature is not configured. Set mailserver_url, login, and password." );
}

if ( ! $pop3->connect( $hostname, $port ) ) {
	wp_die( "Unable to connect to mail server: " . $pop3->ERROR );
}

$count = $pop3->login( $username, $password );
if ( false === $count ) {
	wp_die( "Login failed: " . $pop3->ERROR );
}

for ( $i = 1; $i <= $count; $i++ ) {
	$message = $pop3->get( $i );
	if ( $message ) {
		wp_mail_post( $message );
		$pop3->delete( $i );
	}
}

$pop3->quit();

echo "Mail processing complete.";
