<?php

namespace IMS\LTI\ToolProvider;

/**
 * Interface ConsumerServiceInterface
 *
 * @package IMS\LTI\ToolProvider
 */
interface ConsumerServiceInterface
{

    /**
     * Lookup a Consumer object matching the consumer key from storage
     *
     * @return ConsumerInterface
     */
    public function findByKey($key);

    /**
     * Verify the Nonce against the Consumer.
     * Only allow the request once.
     * Return false to reject.
     *
     * @param ConsumerInterface $consumer
     * @param string $nonce
     * @param integer $timestamp
     * @return boolean
     */
    public function validateNonce(ConsumerInterface $consumer, $nonce, $timestamp);

    /**
     * Create the Nonce record
     *
     * @param ConsumerInterface $consumer
     * @param string $nonce
     * @param integer $timestamp
     * @return boolean
     */
    public function createNonce(ConsumerInterface $consumer, $nonce, $timestamp);

}
