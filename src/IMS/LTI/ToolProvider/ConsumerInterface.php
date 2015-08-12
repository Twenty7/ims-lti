<?php

namespace IMS\LTI\ToolProvider;

/**
 * Interface ConsumerInterface
 *
 * @package IMS\LTI\ToolProvider
 */
interface ConsumerInterface
{

    /**
     * Returns true if the consumer is active
     *
     * @return boolean
     */
    public function isActive();

    /**
     * Returns the consumer key
     *
     * @return string
     */
    public function getConsumerKey();

    /**
     * Returns the consumer secret
     *
     * @return string
     */
    public function getConsumerSecret();

}
