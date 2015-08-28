<?php

namespace IMS\LTI;

use OAuthProvider;
use OAuthException;
use IMS\LTI\Exception\InvalidLTIConsumerInterfaceException;
use IMS\LTI\ToolProvider\ConsumerInterface;
use IMS\LTI\ToolProvider\ConsumerServiceInterface;

class ToolProvider {

	/**
	 * @var ConsumerInterface
	 */
	private $consumer;

	/**
	 * @var ConsumerServiceInterface
	 */
	private $consumerService;

	/**
	 * @var TokenServiceInterface
	 */
	private $tokenService;

	/**
	 * @var OAuthProvider
	 */
	private $oauth;

	private $oauthUri;
	private $postParameters = [];
	private $oauthParameters = [];
	private $ltiParameters = [];
	private $customParameters = [];
	private $extParameters = [];
	protected $timestampExpirationSeconds = 60;
	protected $userParameterKeys = [
		LaunchParameters::USER_ID,
		LaunchParameters::USER_IMAGE,
		LaunchParameters::ROLES,
		LaunchParameters::LIS_PERSON_NAME_FULL,
		LaunchParameters::LIS_PERSON_NAME_FAMILY,
		LaunchParameters::LIS_PERSON_NAME_GIVEN,
		LaunchParameters::LIS_PERSON_SOURCEDID,
	];
	protected $resourceParameterKeys = [
		LaunchParameters::RESOURCE_LINK_ID,
		LaunchParameters::RESOURCE_LINK_TITLE,
		LaunchParameters::RESOURCE_LINK_DESCRIPTION,
	];
	protected $contextParameterKeys = [
		LaunchParameters::CONTEXT_ID,
		LaunchParameters::CONTEXT_TYPE,
		LaunchParameters::CONTEXT_TITLE,
		LaunchParameters::CONTEXT_LABEL,
	];
	protected $consumerParameterKeys = [
		LaunchParameters::TOOL_CONSUMER_INFO_PRODUCT_FAMILY_CODE,
		LaunchParameters::TOOL_CONSUMER_INFO_VERSION,
		LaunchParameters::TOOL_CONSUMER_INSTANCE_CONTACT_EMAIL,
		LaunchParameters::TOOL_CONSUMER_INSTANCE_DESCRIPTION,
		LaunchParameters::TOOL_CONSUMER_INSTANCE_GUID,
		LaunchParameters::TOOL_CONSUMER_INSTANCE_NAME,
		LaunchParameters::TOOL_CONSUMER_INSTANCE_URL,
	];
	private $roles;

	/**
	 * Create a new ToolProvider
	 *
	 * @param ConsumerServiceInterface $consumerService
	 * @param string $oauthUri
	 * @param mixed $postParameters The launch POST parameters
	 */
	public function __construct(ConsumerServiceInterface $consumerService, $oauthUri, $postParameters) {
		$this->consumerService = $consumerService;
		$this->oauthUri = $oauthUri;
		$this->processParameters($postParameters);
	}

	/**
	 * Organize parameters into the appropriate class properties
	 *
	 * @param array $postParameters
	 */
	private function processParameters($postParameters) {
		$this->postParameters = $postParameters;
		foreach ($postParameters as $key => $val) {
			if (substr($key, 0, 6) == 'oauth_') {
				$this->oauthParameters[$key] = $val;
			} elseif (LaunchParameters::isValid($key)) {
				$this->ltiParameters[$key] = $val;
			} elseif (substr($key, 0, 7) == 'custom_') {
				$this->customParameters[$key] = $val;
			} elseif (substr($key, 0, 4) == 'ext_') {
				$this->extParameters[$key] = $val;
			}
		}
	}

	/**
	 * Initialize and return the OAuthProvider object
	 *
	 * @return OAuthProvider
	 */
	public function getOAuthProvider()
	{
		if (is_null($this->oauth)) {
			$this->oauth = new OAuthProvider($this->postParameters);
			$this->oauth->consumerHandler([$this, 'checkConsumerHandler']);
			$this->oauth->timestampNonceHandler([$this, 'checkNonceHandler']);
		}
		return $this->oauth;
	}

	/**
	 * Fetch and return the Consumer Object using the consumerService
	 *
	 * @return ConsumerInterface
	 */
	public function getConsumer()
	{
		if (is_null($this->consumer)) {
			$oauth = $this->getOAuthProvider();
			$this->consumer = $this->consumerService->findByKey($oauth->consumer_key);
		}
		return $this->consumer;
	}

	/**
	 * Validate OAuth Signature
	 *
	 * @return bool
	 * @throws OAuthException
	 */
	public function validRequest() {
		$oauth = $this->getOAuthProvider();

		try {
			$oauth->setRequestTokenPath($this->oauthUri);
			$oauth->checkOAuthRequest($this->oauthUri, OAUTH_HTTP_METHOD_POST);
		} catch (OAuthException $e) {
			$details = OAuthProvider::reportProblem($e);
			throw new OAuthException($e->getMessage() . ' - ' . $details);
		}

		// Todo: Verify LTI Parameters Exist
		// Todo: Return Error Response

		return true;
	}

	/**
	 * Verify OAuth Consumer
	 *
	 * @param OAuthProvider $oauth
	 * @return int
	 * @throws InvalidLTIConsumerInterfaceException
	 */
	public function checkConsumerHandler(OAuthProvider $oauth) {

		$consumer = $this->getConsumer();
		if (!$consumer) {
			return OAUTH_CONSUMER_KEY_UNKNOWN;
		} elseif (!$consumer instanceof ConsumerInterface) {
			throw new InvalidLTIConsumerInterfaceException('Consumer must interface IMS\LTI\ToolProvider\ConsumerInterface');
		} elseif ($consumer->isActive()) {
			$oauth->consumer_secret = $consumer->getConsumerSecret();
			return OAUTH_OK;
		} else {
			return OAUTH_CONSUMER_KEY_REFUSED;
		}
	}

	/**
	 * Check the Timestamp and Nonce
	 *
	 * @param OAuthProvider $oauth
	 * @return int
	 */
	public function checkNonceHandler(OAuthProvider $oauth) {
		$consumer = $this->getConsumer();
		if ($oauth->timestamp < time() - $this->timestampExpirationSeconds) {
			return OAUTH_BAD_TIMESTAMP;
		} elseif(!$this->consumerService->validateNonce($consumer, $oauth->nonce, $oauth->timestamp)) {
			return OAUTH_BAD_NONCE;
		} else {
			$this->consumerService->createNonce($consumer, $oauth->nonce, $oauth->timestamp);
			return OAUTH_OK;
		}
	}

	/**
	 * Return all parameters or a specific set of parameters by parameter type
	 *
	 * @param string $type
	 * @param array $keys
	 * @return array
	 */
	public function getParameters($type = 'lti', $keys = [])
	{
		$type = "{$type}Parameters";
		if (!$keys) {
			return $this->{$type};
		}
		$parameters = [];
		foreach ($keys as $key) {
			if (array_key_exists($key, $this->{$type})) {
				$parameters[$key] = $this->{$type}[$key];
			}
		}
		return $parameters;
	}

	/**
	 * Return an individual parameter
	 *
	 * @param string $key
	 * @param string $type
	 * @return string|null
	 */
	public function getParameter($key, $type = 'lti')
	{
		$type = "{$type}Parameters";
		if (array_key_exists($key, $this->{$type})) {
			return $this->{$type}[$key];
		}
		return null;
	}

	/**
	 * Return all 'LTI' parameters or a specific set of 'LTI' parameters
	 *
	 * @param array $keys
	 * @return array
	 */
	public function getLtiParameters($keys = [])
	{
		return $this->getParameters('lti', $keys);
	}

	/**
	 * Return all 'custom' parameters or a specific set of 'custom' parameters
	 *
	 * @param array $keys
	 * @return array
	 */
	public function getCustomParameters($keys = [])
	{
		return $this->getParameters('custom', $keys);
	}

	/**
	 * Return all 'ext' (Extension) parameters or a specific set of 'ext' parameters
	 *
	 * @param array $keys
	 * @return array
	 */
	public function getExtensionParameters($keys = [])
	{
		return $this->getParameters('ext', $keys);
	}

	/**
	 * Return all 'user' LTI parameters
	 *
	 * @return array
	 */
	public function getUserParameters()
	{
		return $this->getLtiParameters($this->userParameterKeys);
	}

	/**
	 * Return all 'resource' LTI parameters
	 *
	 * @return array
	 */
	public function getResourceParameters()
	{
		return $this->getLtiParameters($this->resourceParameterKeys);
	}

	/**
	 * Return all 'context' LTI parameters
	 *
	 * @return array
	 */
	public function getContextParameters()
	{
		return $this->getLtiParameters($this->contextParameterKeys);
	}

	/**
	 * Return all 'consumer' LTI parameters
	 *
	 * @return array
	 */
	public function getConsumerParameters()
	{
		return $this->getLtiParameters($this->consumerParameterKeys);
	}

	/**
	 * Check if this is a Tool Launch Request
	 *
	 * @return bool
	 */
	public function isLaunchRequest()
	{
		return ($this->ltiParameters[LaunchParameters::LTI_MESSAGE_TYPE] == 'basic-lti-launch-request');
	}

	/**
	 * Return an array of User Roles
	 *
	 * @return array
	 */
	public function getRoles()
	{
		if (is_null($this->roles) && array_key_exists(LaunchParameters::ROLES, $this->ltiParameters)) {
			$roles = explode(',', $this->ltiParameters[LaunchParameters::ROLES]);
			$this->roles = [];
			foreach ($roles as $role) {
				$role = strtolower(trim($role));
				if ($role != '') {
					$this->roles[] = $role;
				}
			}
		}
		return $this->roles;
	}

	/**
	 * Check whether the Launch Parameters have a role
	 *
	 * @param string $role
	 * @return bool
	 */
	public function hasRole($role)
	{
		$roles = array_flip($this->getRoles());
		return (array_key_exists(strtolower($role), $roles));
	}

	/**
	 * Convenience method for checking if the user has 'learner' or 'student' role
	 *
	 * @return bool
	 */
	public function isStudent()
	{
		return ($this->hasRole('learner') || $this->hasRole('student'));
	}

	/**
	 * Convenience method for checking if the user has 'instructor' or 'faculty' or 'staff' role
	 *
	 * @return bool
	 */
	public function isInstructor()
	{
		return ($this->hasRole('instructor') || $this->hasRole('faculty') || $this->hasRole('staff'));
	}

	/**
	 * Convenience method for checking if the user has 'contentdeveloper' role
	 *
	 * @return bool
	 */
	public function isContentDeveloper()
	{
		return ($this->hasRole('contentdeveloper'));
	}
}
