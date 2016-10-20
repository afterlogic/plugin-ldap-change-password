<?php

class_exists('CApi') or die();

CApi::Inc('common.plugins.change-password');

class CLDAPChangePasswordPlugin extends AApiChangePasswordPlugin
{
	/**
	 * @var
	 */
	protected $oAdminAccount;

	/**
	 * @param CApiPluginManager $oPluginManager
	 */
	public function __construct(CApiPluginManager $oPluginManager)
	{
		parent::__construct('1.0', $oPluginManager);

		$this->oAdminAccount = null;
	}
	
	/**
	 * @staticvar CLdapConnector|null $oLdap
	 * @param CAccount $oAccount
	 * @return CLdapConnector|bool
	 */
	private function Ldap($oAccount)
	{
		if (!$oAccount)
		{
			return false;
		}

		static $oLdap = null;
		if (null === $oLdap)
		{
			CApi::Inc('common.ldap');

			$oLdap = new CLdapConnector((string) CApi::GetConf('plugins.ldap-change-password.config.search-dn', ''));
			$oLdap = $oLdap->Connect(
				(string) CApi::GetConf('plugins.ldap-change-password.config.host', '127.0.0.1'),
				(int) CApi::GetConf('plugins.ldap-change-password.config.port', 389),
				(string) CApi::GetConf('plugins.ldap-change-password.config.bind-dn', ''),
				(string) CApi::GetConf('plugins.ldap-change-password.config.bind-password', ''),
				(string) CApi::GetConf('plugins.ldap-change-password.config.host-backup', ''),
				(int) CApi::GetConf('plugins.ldap-change-password.config.port-backup', 389)
			) ? $oLdap : false;
		}

		return $oLdap;
	}
	

	/**
	 * @param CAccount $oAccount
	 * @return bool
	 */
	protected function validateIfAccountCanChangePassword($oAccount)
	{
		return true;
	}

	/**
	 * @param CAccount $oAccount
	 */
	public function ChangePasswordProcess($oAccount)
	{
		if (0 < strlen($oAccount->PreviousMailPassword) &&
			$oAccount->PreviousMailPassword !== $oAccount->IncomingMailPassword)
		{
			$oLdap = $this->Ldap($oAccount);

			$sSearchAttribute = (string) CApi::GetConf('plugins.ldap-change-password.config.search-attribute', 'mail');
			if ($oLdap && $oLdap->Search('('. $sSearchAttribute .'='.$oAccount->Email.')') && 1 === $oLdap->ResultCount())
			{
				$aData = $oLdap->ResultItem();
				$sDn = !empty($aData['dn']) ? $aData['dn'] : '';

				if (!empty($sDn) && $oLdap->ReBind($sDn, $oAccount->PreviousMailPassword))
				{
					$aModifyEntry = array(
						(string) CApi::GetConf('plugins.ldap-change-password.config.password-attribute', 'password') => $this->PasswordHash($oAccount->IncomingMailPassword)
					);
					$oLdap->SetSearchDN('');
					$oLdap->Modify($sDn, $aModifyEntry);
				}
				try
				{
				}
				catch (Exception $oException)
				{
					throw new CApiManagerException(Errs::UserManager_AccountNewPasswordUpdateError);
				}
			}
			else
			{
				throw new CApiManagerException(Errs::UserManager_AccountNewPasswordUpdateError);
			}
		}
	}
	
	function PasswordHash($sPassword)
	{
		$sEncType = strtolower((string) CApi::GetConf('plugins.ldap-change-password.config.password-type', 'clear'));

		$sPasswordHash = '';
		switch($sEncType)
		{
			case 'clear':
				$sPasswordHash = $sPassword;
				break;
			case 'md5':
				$sMd5Hash = md5($sPassword);
				for ( $i = 0; $i < 32; $i += 2 )
				{
					$sPasswordHash .= chr( hexdec( $sMd5Hash{ $i + 1 } ) + hexdec( $sMd5Hash{ $i } ) * 16 );
				}
				$sPasswordHash = '{MD5}'.base64_encode($sPasswordHash);
				break;
			case 'crypt':
			default:
				$sPasswordHash = '{CRYPT}'.crypt($sPassword);
				break;
		}

		return $sPasswordHash;
	}	
}

return new CLDAPChangePasswordPlugin($this);
