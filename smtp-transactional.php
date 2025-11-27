<?php
/**
 * Plugin Name: SMTP Transactional
 * Description: Configura el envío SMTP para WordPress/WooCommerce, con cifrado de contraseña y prueba de correo.
 * Version: 1.0.0
 * Author: Codex Assistant
 */

if (!defined('ABSPATH')) {
    exit;
}

const SMTP_TRANSACTIONAL_OPTION_KEY = 'smtp_transactional_settings';
const SMTP_TRANSACTIONAL_MESSAGE_KEY = 'smtp_transactional_messages';

add_action('admin_menu', 'smtp_transactional_add_menu');
add_action('admin_init', 'smtp_transactional_handle_requests');
add_action('phpmailer_init', 'smtp_transactional_configure_phpmailer');

/**
 * Agrega la página de opciones bajo Ajustes.
 */
function smtp_transactional_add_menu(): void {
    add_options_page(
        __('SMTP Transactional', 'smtp-transactional'),
        __('SMTP Transactional', 'smtp-transactional'),
        'manage_options',
        'smtp-transactional',
        'smtp_transactional_render_page'
    );
}

/**
 * Devuelve la configuración con valores por defecto.
 */
function smtp_transactional_get_settings(): array {
    $defaults = [
        'host'         => '',
        'port'         => 587,
        'encryption'   => 'tls',
        'from_email'   => '',
        'from_name'    => '',
        'app_password' => '',
        'reply_to'     => '',
    ];

    $stored = get_option(SMTP_TRANSACTIONAL_OPTION_KEY, []);

    if (!is_array($stored)) {
        $stored = [];
    }

    return wp_parse_args($stored, $defaults);
}

/**
 * Maneja guardado de opciones, envío de prueba y chequeo de conexión.
 */
function smtp_transactional_handle_requests(): void {
    if (!current_user_can('manage_options')) {
        return;
    }

    if (isset($_POST['smtp_transactional_save']) || isset($_POST['smtp_transactional_check_connection'])) {
        check_admin_referer('smtp_transactional_save_settings');
        if (isset($_POST['smtp_transactional_save'])) {
            smtp_transactional_save_settings();
        }
        if (isset($_POST['smtp_transactional_check_connection'])) {
            check_admin_referer('smtp_transactional_check_connection', 'smtp_transactional_check_connection_nonce');
            smtp_transactional_check_connection();
        }
    }

    if (isset($_POST['smtp_transactional_send_test'])) {
        check_admin_referer('smtp_transactional_send_test');
        smtp_transactional_send_test_email();
    }
}

/**
 * Sanitiza y guarda la configuración.
 */
function smtp_transactional_save_settings(): void {
    $settings = smtp_transactional_get_settings();

    $settings['host']       = sanitize_text_field(wp_unslash($_POST['host'] ?? ''));
    $settings['port']       = absint($_POST['port'] ?? 0) ?: 587;

    $encryption             = sanitize_text_field(wp_unslash($_POST['encryption'] ?? ''));
    $allowed_encryption     = ['', 'ssl', 'tls'];
    $settings['encryption'] = in_array($encryption, $allowed_encryption, true) ? $encryption : '';

    $settings['from_email'] = sanitize_email(wp_unslash($_POST['from_email'] ?? ''));
    $settings['from_name']  = sanitize_text_field(wp_unslash($_POST['from_name'] ?? ''));
    $settings['reply_to']   = sanitize_email(wp_unslash($_POST['reply_to'] ?? ''));

    if (!empty($_POST['app_password'])) {
        $raw_password              = sanitize_text_field(wp_unslash($_POST['app_password']));
        $settings['app_password'] = smtp_transactional_encrypt($raw_password);
    }

    update_option(SMTP_TRANSACTIONAL_OPTION_KEY, $settings);
    add_settings_error(SMTP_TRANSACTIONAL_MESSAGE_KEY, 'settings_saved', __('Configuración guardada.', 'smtp-transactional'), 'updated');
}

/**
 * Envía un correo de prueba usando wp_mail().
 */
function smtp_transactional_send_test_email(): void {
    $test_email = sanitize_email(wp_unslash($_POST['test_email'] ?? ''));
    $settings   = smtp_transactional_get_settings();

    if (empty($settings['host']) || empty($settings['from_email'])) {
        add_settings_error(SMTP_TRANSACTIONAL_MESSAGE_KEY, 'missing_settings', __('Completa los datos SMTP antes de enviar una prueba.', 'smtp-transactional'));
        return;
    }

    if (!is_email($test_email)) {
        add_settings_error(SMTP_TRANSACTIONAL_MESSAGE_KEY, 'invalid_email', __('La dirección de prueba no es válida.', 'smtp-transactional'));
        return;
    }

    $subject = __('Prueba de SMTP Transactional', 'smtp-transactional');
    $body    = __('Este es un correo de prueba enviado desde la configuración SMTP Transactional.', 'smtp-transactional');

    $sent = wp_mail($test_email, $subject, $body);

    if ($sent) {
        add_settings_error(SMTP_TRANSACTIONAL_MESSAGE_KEY, 'test_sent', __('Correo de prueba enviado correctamente.', 'smtp-transactional'), 'updated');
    } else {
        add_settings_error(SMTP_TRANSACTIONAL_MESSAGE_KEY, 'test_failed', __('No se pudo enviar el correo de prueba. Verifica la configuración o activa WP_DEBUG para más detalles.', 'smtp-transactional'));
    }
}

/**
 * Prueba la conexión al puerto SMTP mediante fsockopen().
 */
function smtp_transactional_check_connection(): void {
    $settings = smtp_transactional_get_settings();

    if (empty($settings['host']) || empty($settings['port'])) {
        add_settings_error(SMTP_TRANSACTIONAL_MESSAGE_KEY, 'missing_host', __('Define host y puerto antes de probar la conexión.', 'smtp-transactional'));
        return;
    }

    $errno  = 0;
    $errstr = '';
    $fp     = @fsockopen($settings['host'], $settings['port'], $errno, $errstr, 5);

    if ($fp) {
        fclose($fp);
        add_settings_error(SMTP_TRANSACTIONAL_MESSAGE_KEY, 'connection_ok', __('Conectado al servidor SMTP.', 'smtp-transactional'), 'updated');
    } else {
        $message = sprintf(__('No se pudo conectar: %1$s (%2$s). ¿Puerto bloqueado o credenciales incorrectas?', 'smtp-transactional'), $errstr ?: __('error desconocido', 'smtp-transactional'), $errno);
        add_settings_error(SMTP_TRANSACTIONAL_MESSAGE_KEY, 'connection_failed', $message);
    }
}

/**
 * Aplica la configuración al PHPMailer global.
 */
function smtp_transactional_configure_phpmailer($phpmailer): void {
    $settings = smtp_transactional_get_settings();

    if (empty($settings['host']) || empty($settings['from_email']) || empty($settings['app_password'])) {
        return;
    }

    $decrypted_password = smtp_transactional_decrypt($settings['app_password']);

    $phpmailer->isSMTP();
    $phpmailer->Host       = $settings['host'];
    $phpmailer->Port       = (int) $settings['port'];
    $phpmailer->SMTPAuth   = true;
    $phpmailer->SMTPSecure = $settings['encryption'] ?: '';
    $phpmailer->Username   = $settings['from_email'];
    $phpmailer->Password   = $decrypted_password;
    $phpmailer->SMTPDebug  = (defined('WP_DEBUG') && WP_DEBUG) ? 2 : 0;
    $phpmailer->Debugoutput = 'error_log';

    $from_email = $settings['from_email'];
    $from_name  = $settings['from_name'] ?: $settings['from_email'];

    $phpmailer->setFrom($from_email, $from_name);

    if (!empty($settings['reply_to']) && is_email($settings['reply_to'])) {
        try {
            $phpmailer->addReplyTo($settings['reply_to'], $from_name);
        } catch (\Exception $e) {
            // Ignorar problemas al asignar Reply-To para no bloquear el envío.
        }
    }
}

/**
 * Renderiza la página de ajustes.
 */
function smtp_transactional_render_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die(__('No tienes permisos para acceder a esta página.', 'smtp-transactional'));
    }

    $settings = smtp_transactional_get_settings();
    ?>
    <div class="wrap">
        <h1><?php esc_html_e('SMTP Transactional', 'smtp-transactional'); ?></h1>
        <?php settings_errors(SMTP_TRANSACTIONAL_MESSAGE_KEY); ?>

        <form method="post">
            <?php
            wp_nonce_field('smtp_transactional_save_settings');
            wp_nonce_field('smtp_transactional_check_connection', 'smtp_transactional_check_connection_nonce');
            ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="host"><?php esc_html_e('Servidor SMTP (host)', 'smtp-transactional'); ?></label></th>
                    <td><input name="host" type="text" id="host" value="<?php echo esc_attr($settings['host']); ?>" class="regular-text" required></td>
                </tr>
                <tr>
                    <th scope="row"><label for="port"><?php esc_html_e('Puerto', 'smtp-transactional'); ?></label></th>
                    <td><input name="port" type="number" id="port" value="<?php echo esc_attr((string) $settings['port']); ?>" class="small-text" required></td>
                </tr>
                <tr>
                    <th scope="row"><label for="encryption"><?php esc_html_e('Encriptación', 'smtp-transactional'); ?></label></th>
                    <td>
                        <select name="encryption" id="encryption">
                            <?php
                            $options = [
                                ''     => __('Ninguna', 'smtp-transactional'),
                                'ssl'  => __('SSL', 'smtp-transactional'),
                                'tls'  => __('TLS', 'smtp-transactional'),
                            ];
                            foreach ($options as $value => $label) :
                                ?>
                                <option value="<?php echo esc_attr($value); ?>" <?php selected($settings['encryption'], $value); ?>><?php echo esc_html($label); ?></option>
                                <?php
                            endforeach;
                            ?>
                        </select>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="from_email"><?php esc_html_e('Email saliente (usuario SMTP)', 'smtp-transactional'); ?></label></th>
                    <td><input name="from_email" type="email" id="from_email" value="<?php echo esc_attr($settings['from_email']); ?>" class="regular-text" required></td>
                </tr>
                <tr>
                    <th scope="row"><label for="from_name"><?php esc_html_e('Nombre del remitente', 'smtp-transactional'); ?></label></th>
                    <td><input name="from_name" type="text" id="from_name" value="<?php echo esc_attr($settings['from_name']); ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="reply_to"><?php esc_html_e('Reply To', 'smtp-transactional'); ?></label></th>
                    <td><input name="reply_to" type="email" id="reply_to" value="<?php echo esc_attr($settings['reply_to']); ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="app_password"><?php esc_html_e('Contraseña de aplicación', 'smtp-transactional'); ?></label></th>
                    <td>
                        <input name="app_password" type="password" id="app_password" value="" class="regular-text" placeholder="<?php echo esc_attr($settings['app_password'] ? __('(oculta, deja en blanco para no cambiar)', 'smtp-transactional') : '********'); ?>">
                        <p class="description"><?php esc_html_e('Guardada cifrada. Nunca se muestra en texto plano.', 'smtp-transactional'); ?></p>
                    </td>
                </tr>
            </table>
            <p class="submit">
                <button type="submit" name="smtp_transactional_save" class="button-primary"><?php esc_html_e('Guardar cambios', 'smtp-transactional'); ?></button>
                <button type="submit" name="smtp_transactional_check_connection" class="button"><?php esc_html_e('Probar conexión', 'smtp-transactional'); ?></button>
            </p>
        </form>

        <hr>

        <h2><?php esc_html_e('Enviar email de prueba', 'smtp-transactional'); ?></h2>
        <form method="post">
            <?php wp_nonce_field('smtp_transactional_send_test'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="test_email"><?php esc_html_e('Enviar a', 'smtp-transactional'); ?></label></th>
                    <td><input name="test_email" type="email" id="test_email" value="" class="regular-text" required></td>
                </tr>
            </table>
            <p class="submit">
                <button type="submit" name="smtp_transactional_send_test" class="button-secondary"><?php esc_html_e('Enviar correo de prueba', 'smtp-transactional'); ?></button>
            </p>
        </form>
    </div>
    <?php
}

/**
 * Cifra la contraseña (openssl si está disponible).
 */
function smtp_transactional_encrypt(string $value): string {
    $value = trim($value);
    if ($value === '') {
        return '';
    }

    if (function_exists('openssl_encrypt')) {
        $key  = smtp_transactional_encryption_key();
        $iv   = smtp_transactional_random_bytes(openssl_cipher_iv_length('AES-256-CBC'));
        $cipher = openssl_encrypt($value, 'AES-256-CBC', $key, 0, $iv);
        if ($cipher !== false) {
            return base64_encode($iv . '::' . $cipher);
        }
    }

    return base64_encode($value);
}

/**
 * Descifra la contraseña almacenada.
 */
function smtp_transactional_decrypt(string $stored): string {
    if ($stored === '') {
        return '';
    }

    $decoded = base64_decode($stored, true);
    if ($decoded === false) {
        return '';
    }

    if (function_exists('openssl_decrypt') && strpos($decoded, '::') !== false) {
        [$iv, $cipher] = explode('::', $decoded, 2);
        $plain = openssl_decrypt($cipher, 'AES-256-CBC', smtp_transactional_encryption_key(), 0, $iv);
        if ($plain !== false) {
            return $plain;
        }
    }

    return $decoded;
}

/**
 * Genera la clave de cifrado basada en las salts de WordPress.
 */
function smtp_transactional_encryption_key(): string {
    return hash('sha256', wp_salt('smtp-transactional'));
}

/**
 * Genera bytes seguros para IV.
 */
function smtp_transactional_random_bytes(int $length): string {
    if (function_exists('random_bytes')) {
        return random_bytes($length);
    }

    if (function_exists('openssl_random_pseudo_bytes')) {
        return openssl_random_pseudo_bytes($length);
    }

    // Fallback poco frecuente; no se expone la contraseña en texto plano.
    $fallback = '';
    for ($i = 0; $i < $length; $i++) {
        $fallback .= chr(mt_rand(0, 255));
    }
    return $fallback;
}
