<?php

namespace SilverStripe\GraphQL\Scaffolding\Interfaces;

/**
 * Applied to classes that resolve queries or mutations
 */
interface ResolverInterface
{
    /**
     * @param DataObjectInterface $object
     * @param array $args
     * @param array $context
     * @param ResolverInfo $info
     * @return mixed
     */
    public function resolve($object, $args, $context, $info);
}
