<?php
/**
 * Bootstrap file for setting the ABSPATH constant and loading the wp-config.php file.
 *
 * @package WordPress
 */

// Define ABSPATH as this file's directory.
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

// Load wp-config.php
if ( file_exists( ABSPATH . 'wp-config.php' ) ) {

    /** The config file resides in ABSPATH */
    require_once ABSPATH . 'wp-config.php';

} elseif ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {

    /** The config file resides one level above ABSPATH but is not part of another install. */
    require_once dirname( ABSPATH ) . '/wp-config.php';

} else {

    // No config found.
    header( 'Location: setup-config.php' );
    exit;
}
