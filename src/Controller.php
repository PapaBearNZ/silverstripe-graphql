<?php

namespace SilverStripe\GraphQL;

use SilverStripe\Control\Controller as BaseController;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Control\Director;
use SilverStripe\GraphQL\Auth\Handler;
use SilverStripe\ORM\Versioning\Versioned;
use Exception;
use SilverStripe\Security\Permission;
use SilverStripe\Security\Security;

use SilverStripe\Dev\Debug;
/**
 * Top level controller for handling graphql requests.
 * @todo CSRF protection (or token-based auth)
 */
class Controller extends BaseController
{
    /**
     * @var Manager
     */
    protected $manager;

    /**
     * Handles requests to /graphql (index action)
     *
     * @param HTTPRequest $request
     * @return HTTPResponse
     */
    public function index(HTTPRequest $request)
    {
        $stage = $request->param('Stage');
        if ($stage && in_array($stage, [Versioned::DRAFT, Versioned::LIVE])) {
            Versioned::set_stage($stage);
        }

        // Check for a possible CORS preflight request and handle if necessary
        // Refer issue 66:  https://github.com/silverstripe/silverstripe-graphql/issues/66
        $corsConfig = Config::inst()->get('SilverStripe\GraphQL', 'cors');
        $corsEnabled = true; // Default to have CORS turned on.

        if ($corsConfig && isset($corsConfig['Enabled']) && !$corsConfig['Enabled']) {
            // Dev has turned off CORS
            $corsEnabled = false;
        }
        if ($corsEnabled && $request->httpMethod() == 'OPTIONS') {
            // CORS config is enabled and the request is an OPTIONS pre-flight.
            // Process the CORS config and add appropriate headers.
            return $this->processCorsConfig($request);
        }

        $contentType = $request->getHeader('Content-Type') ?: $request->getHeader('content-type');
        $isJson = preg_match('#^application/json\b#', $contentType);
        if ($isJson) {
            $rawBody = $request->getBody();
            $data = json_decode($rawBody ?: '', true);
            $query = isset($data['query']) ? $data['query'] : null;
            $variables = isset($data['variables']) ? json_decode($data['variables'], true) : null;
        } else {
            $query = $request->requestVar('query');
            $variables = json_decode($request->requestVar('variables'), true);
        }

        $this->setManager($manager = $this->getManager());

        try {
            // Check authentication
            $member = $this->getAuthHandler()->requireAuthentication($request);
            if ($member) {
                $manager->setMember($member);
            }

            // Check authorisation
            $permissions = $request->param('Permissions');
            if ($permissions) {
                if (!$member) {
                    throw new \Exception("Authentication required");
                }
                $allowed = Permission::checkMember($member, $permissions);
                if (!$allowed) {
                    throw new \Exception("Not authorised");
                }
            }

            // Run query
            $result = $manager->query($query, $variables);
        } catch (Exception $exception) {
            $error = ['message' => $exception->getMessage()];

            if (Director::isDev()) {
                $error['code'] = $exception->getCode();
                $error['file'] = $exception->getFile();
                $error['line'] = $exception->getLine();
                $error['trace'] = $exception->getTrace();
            }

            $result = [
                'errors' => [$error]
            ];
        }

        $response = $this->processCorsConfig($request, new HTTPResponse(json_encode($result)));
        return $response->addHeader('Content-Type', 'application/json');
    }

    /**
     * @return Manager
     */
    public function getManager()
    {
        if ($this->manager) {
            return $this->manager;
        }

        // Get a service rather than an instance (to allow procedural configuration)
        $config = Config::inst()->get('SilverStripe\GraphQL', 'schema');
        $manager = Manager::createFromConfig($config);

        return $manager;
    }

    /**
     * @param Manager $manager
     */
    public function setManager($manager)
    {
        $this->manager = $manager;
    }

    /**
     * Get an instance of the authorization Handler to manage any authentication requirements
     *
     * @return Handler
     */
    public function getAuthHandler()
    {
        return new Handler;
    }

    /**
     * Process the CORS config options and add the appropriate headers to the response.
     *
     * @param HTTPRequest $request
     * @param HTTPResponse $response
     * @return HTTPResponse
     */
    private function processCorsConfig(HTTPRequest $request, HTTPResponse $response = null)
    {
        if (!$response) {
            $response = new HTTPResponse();
        }
        $corsConfig = Config::inst()->get('SilverStripe\GraphQL', 'cors');

        // Allow Origins header.
        if ($corsConfig['Allow-Origin'] && is_array($corsConfig['Allow-Origin'])) {
            $origin = $request->getHeader('Origin');
            if ($origin) {
                $originAuthorised = false;
                foreach ($corsConfig['Allow-Origin'] as $allowedOrigin) {
                    if ($allowedOrigin == $origin) {
                        $response->addHeader("Access-Control-Allow-Origin", $origin);
                        $originAuthorised = true;
                        break;
                    }
                }

                if ($originAuthorised) {
                    return $this->httpError(403, "Access Forbidden");
                }
            }
        } elseif ($corsConfig['Allow-Origin']) {
            $response->addHeader('Access-Control-Allow-Origin', $corsConfig['Allow-Origin']);
        } else {
            $response->addHeader('Access-Control-Allow-Origin', '*');
        }

        // Allow Headers header.
        if ($corsConfig['Allow-Headers']) {
            $response->addHeader('Access-Control-Allow-Headers', $corsConfig['Allow-Headers']);
        } else {
            $response->addHeader('Access-Control-Allow-Headers', '*');
        }

        // Allow Methods header.
        if ($corsConfig['Allow-Methods']) {
            $response->addHeader('Access-Control-Allow-Methods', $corsConfig['Allow-Methods']);
        } else {
            $response->addHeader('Access-Control-Allow-Headers', 'OPTIONS, POST, GET, PUT, DELETE');
        }

        // Max Age header.
        if ($corsConfig['Max-Age']) {
            $response->addHeader('Access-Control-Max-Age', $corsConfig['Max-Age']);
        } else {
            $response->addHeader('Access-Control-Max-Age', 86400);
        }

        return $response;
    }
}
