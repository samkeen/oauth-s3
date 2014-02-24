require 'sinatra'
require 'google/api_client'
require 'google/api_client/client_secrets'
#require 'json'
require 'yaml'
require 'rack-flash'

#
# See https://github.com/ephekt/gmail-oauth2-sinatra
# Turn this into GoogleAuth-S3 bucket
#

configure do
  this_dir = File.dirname(__FILE__)
  # setting one option
  config = YAML.load_file("#{this_dir}/config.yml")
  set :g_credentials, {'web' => config['web']}
  # client_id needed in mult places so set an easy access key
  set :g_client_id, config['web']['client_id']
  set :g_scopes, config['scopes']
  set :application_settings, config['application_settings']
  set :unauthenticated_routes, %w(/ /logout /authenticate)
end


helpers do

  def logged_in?
    session.has_key?(:token)
  end

end

enable :sessions
use Rack::Flash

# enforce authentication on all routes except those in whitelist
before // do
  pass if settings.unauthenticated_routes.include? request.path_info
  authenticate!
end

get '/' do
  require 'securerandom'
  state = SecureRandom.hex(16)
  session['state'] = state
  erb :index,
      :locals => {
        :client_id => settings.g_client_id,
        :state     => state,
        :scopes    => settings.g_scopes.join(' ')
      }
end

get '/home' do
  erb :home
end

# @todo Move out of global scope
# Build the global client
$credentials = Google::APIClient::ClientSecrets.new(settings.g_credentials)

$authorization = Signet::OAuth2::Client.new(
    :authorization_uri => $credentials.authorization_uri,
    :token_credential_uri => $credentials.token_credential_uri,
    :client_id => $credentials.client_id,
    :client_secret => $credentials.client_secret,
    :redirect_uri => $credentials.redirect_uris.first,
    :scope => settings.g_scopes)
$client = Google::APIClient.new(settings.application_settings)

post '/authenticate' do

  # @see https://github.com/google/google-api-ruby-client
  if !session[:token]

    # check for oauth2 'state'.
    # @see https://developers.google.com/+/web/signin/server-side-flow
    unless session[:state] == params[:state]
      halt 401, 'Client oauth state value does not match'
    end

    # Exchange 'code' for access token
    $authorization.code = request.body.read
    $authorization.fetch_access_token!
    $client.authorization = $authorization

    session[:token] = storable_token($client.authorization)

    google_id = get_google_id

    #GET https://www.googleapis.com/plus/v1/people/me?fields=emails&key={YOUR_API_KEY}
    #Authorization:  Bearer ya29.1.AADtN_VwI9gTvNatXdII6PU8_85ps0mi15aF3ip7JTIq4XgAQuGB2seDRC0ANw

    plus = $client.discovered_api('plus', 'v1')
    # Get the list of people as JSON and return it.
    begin
      result = $client.execute!(plus.people.get, :userId => google_id)
      profile = JSON.parse(result.response.body)
      domain = profile['domain']

      if domain != 'janrain.com'
        logout
        redirect to('/')
      end


    rescue Exception => e
      halt 501, e.to_s
    end


    status 200
  else
    # @todo determine consistent response format
    content_type :json
    'Current user is already connected.'.to_json
  end

end

##
# Disconnect the user by revoking the stored token and removing session objects.
get '/logout' do
  logout
  redirect to('/')
end

def storable_token(authorization)
  {
      :refresh_token => authorization.refresh_token,
      :access_token => authorization.access_token,
      :expires_in => authorization.expires_in,
      :issued_at => Time.at(authorization.issued_at)
  }
end

def authenticate!
  # Verify oauth token in session
  unless session[:token]
    halt 401, 'No authentication token present'
  end
end

def logout
  if session[:token]
    token = session[:token][:refresh_token] || session[:token][:access_token]
    # You could reset the state at this point, but as-is it will still stay unique
    # to this user and we're avoiding resetting the client state.
    # session.delete(:state)
    session.delete(:token)

    # Send the revocation request and return the result.
    # @todo test invalid response here
    revokePath = 'https://accounts.google.com/o/oauth2/revoke?token=' + token
    uri = URI.parse(revokePath)
    request = Net::HTTP.new(uri.host, uri.port)
    request.use_ssl = true
    response = request.get(uri.request_uri)
  end
  flash[:notice] = "You've been logged out"
end

# the id token is base64 encoded JSON
# @see https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
def get_google_id
  id_token = $client.authorization.id_token
  encoded_json_body = id_token.split('.')[1]
  # Base64 must be a multiple of 4 characters long, trailing with '='
  encoded_json_body += (['='] * (encoded_json_body.length % 4)).join('')
  json_body = Base64.decode64(encoded_json_body)
  body = JSON.parse(json_body)
  # You can read the Google user ID in the ID token.
  # "sub" represents the ID token subscriber which in our case
  # is the user ID. This sample does not use the user ID.
  body['sub']
end

