<?php
/**
 * cipher.php
 * @author kohei hieda
 *
 */
if (strpos(ini_get('include_path'), 'pear') === false) {
	if (!function_exists('_pear_call_destructors')) {
		ini_set('include_path', ini_get('include_path') . PATH_SEPARATOR . dirname(dirname(dirname(__FILE__))) . DIRECTORY_SEPARATOR . 'Lib' . DIRECTORY_SEPARATOR . 'PEAR');
		require_once('PEAR.php');
	}
}

ini_set('include_path', ini_get('include_path') . PATH_SEPARATOR . dirname(dirname(dirname(__FILE__))) . DIRECTORY_SEPARATOR . 'Lib');

require_once('Crypt/Blowfish.php');

class CipherBehavior extends ModelBehavior {

	var $default = array(
		'autoEncrypt'=>false,
		'autoDecrypt'=>false,
		'target'=>null);

	var $settings = array();

	/**
	 * setup
	 * @param $model
	 * @param $config
	 */
	function setup(&$model, $config = array()) {
		if (!isset($this->settings[$model->alias])) {
			$this->settings[$model->alias] = $this->default;
		}

		$this->settings[$model->alias] = am($this->settings[$model->alias], is_array($config) ? $config : array());
	}

	public function staticEncrypt(&$model, $key, $value) {
		if ($value == '') {
			return $value;
		}
		$blowfish = new Crypt_Blowfish($key);
		return base64_encode($blowfish->encrypt(base64_encode($value)));
	}

	public function staticDecrypt(&$model, $key, $value) {
		if ($value == '') {
			return $value;
		}
		$blowfish = new Crypt_Blowfish($key);
		return base64_decode($blowfish->decrypt(base64_decode($value)));
	}

	public function beforeFind(&$model, $query) {
		if ($this->settings[$model->alias]['autoEncrypt']) {
			if (!empty($query['conditions'])) {
				foreach ($query['conditions'] as $key=>$value) {
					if ($this->_isTarget($this->settings[$model->alias]['target'], $key)) {
						$query['conditions'][$key] = $this->_encrypt($value);
					}
				}
			}
		}
		return $query;
	}

	public function afterFind(&$model, $results, $primary) {
		if ($this->settings[$model->alias]['autoDecrypt']) {
			if ($primary) {
				foreach (array_keys($results) as $key) {
					$results[$key] = $this->decrypt($model, $results[$key]);
				}
			}
		}

		return $results;
	}

	public function beforeSave(&$Model) {
		if ($this->settings[$Model->alias]['autoEncrypt']) {
			$Model->data = $this->encrypt($Model, $Model->data);
		}

		return true;
	}

	/**
	 * encrypt
	 * @param $model
	 * @param $data
	 * @return string
	 */
	function encrypt(&$model, $data) {
		$ret = null;

		if (is_array($data) && isset($data[$model->alias])) {
			foreach ($data[$model->alias] as $key=>$value) {
				if ($this->_isTarget($this->settings[$model->alias]['target'], $key)){
					$ret[$model->alias][$key] = $this->_encrypt($value);
				} else {
					$ret[$model->alias][$key] = $value;
				}
			}
		} else {
			$ret = $this->_encrypt($data);
		}

		return $ret;
	}

	/**
	 * decrypt
	 * @param $model
	 * @param $data
	 * @return string
	 */
	function decrypt(&$model, $data) {
		$ret = null;

		if (is_array($data) && isset($data[$model->alias])) {
			foreach ($data[$model->alias] as $key=>$value) {
				if ($this->_isTarget($this->settings[$model->alias]['target'], $key)){
					$ret[$model->alias][$key] = $this->_decrypt($value);
				} else {
					$ret[$model->alias][$key] = $value;
				}
			}
		} else if (!is_array($data)) {
			$ret = $this->_decrypt($data);
		} else {
			$ret = $data;
		}

		return $ret;
	}

	/**
	 * _encrypt
	 * @param $value
	 * @return string
	 */
	function _encrypt($value) {
		$ret = '';
		if ($value != '') {
			//$ret = base64_encode(mcrypt_encrypt(MCRYPT_BLOWFISH, Configure::read('Security.salt'), base64_encode($value), MCRYPT_MODE_ECB));
			//$blowfish = Crypt_Blowfish::factory('cbc', Configure::read('Security.salt'), substr(md5(uniqid(rand(), 1)), 0, 8));
			$blowfish = new Crypt_Blowfish(Configure::read('Security.salt'));
			$ret = base64_encode($blowfish->encrypt(base64_encode($value)));
		}
		return $ret;
	}

	/**
	 * _decrypt
	 * @param $value
	 * @return string
	 */
	function _decrypt($value) {
		$ret = '';
		if ($value != '') {
			//$ret = base64_decode(mcrypt_decrypt(MCRYPT_BLOWFISH, Configure::read('Security.salt'), base64_decode($value), MCRYPT_MODE_ECB));
			$blowfish = new Crypt_Blowfish(Configure::read('Security.salt'));
			$ret = base64_decode($blowfish->decrypt(base64_decode($value)));
		}
		return $ret;
	}

	/**
	 * _isTarget
	 * @param $target
	 * @param $key
	 * @return boolean
	 */
	function _isTarget($target, $key) {
		if (strpos($key, '.') !== false) {
			$key = array_pop(explode('.', $key, 2));
		}
		if (is_array($target)) {
			if (in_array($key, $target)) {
				return true;
			}
		} else {
			if ($target == $key) {
				return true;
			}
		}

		return false;
	}

}
