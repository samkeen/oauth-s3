require 'sinatra'
require 'oauth2'
require 'json'
require 'yaml'

#
# See https://github.com/ephekt/gmail-oauth2-sinatra
# Turn this into GoogleAuth-S3 bucket
#


configure do
  this_dir = File.dirname(__FILE__)
  # setting one option
  set :config, YAML.load_file("#{this_dir}/config.yml")
end

enable :sessions

get '/' do
  require 'securerandom'
  state = SecureRandom.hex(16)
  session['state'] = state
  erb :index,
      :locals => {
        :client_id => settings.config['google_client_id'],
        :state     => state
      }
end

# @todo Move out of global scope
# Build the global client
$credentials = Google::APIClient::ClientSecrets.load
$authorization = Signet::OAuth2::Client.new(
    :authorization_uri => $credentials.authorization_uri,
    :token_credential_uri => $credentials.token_credential_uri,
    :client_id => $credentials.client_id,
    :client_secret => $credentials.client_secret,
    :redirect_uri => $credentials.redirect_uris.first,
    :scope => PLUS_LOGIN_SCOPE)
$client = Google::APIClient.new

post '/authorize' do

  # @see https://github.com/google/google-api-ruby-client
  if !session[:token]
    # Make sure that the state we set on the client matches the state sent
    # in the request to protect against request forgery.
    if session[:state] == params[:state]
      # Upgrade the code into a token object.
      $authorization.code = request.body.read
      $authorization.fetch_access_token!
      $client.authorization = $authorization

      id_token = $client.authorization.id_token
      encoded_json_body = id_token.split('.')[1]
      # Base64 must be a multiple of 4 characters long, trailing with '='
      encoded_json_body += (['='] * (encoded_json_body.length % 4)).join('')
      json_body = Base64.decode64(encoded_json_body)
      body = JSON.parse(json_body)
      # You can read the Google user ID in the ID token.
      # "sub" represents the ID token subscriber which in our case
      # is the user ID. This sample does not use the user ID.
      gplus_id = body['sub']

      # Serialize and store the token in the user's session.
      token_pair = TokenPair.new
      token_pair.update_token!($client.authorization)
      session[:token] = token_pair
    else
      halt 401, 'The client state does not match the server state.'
    end
    status 200
  else
    content_type :json
    'Current user is already connected.'.to_json
  end

end
