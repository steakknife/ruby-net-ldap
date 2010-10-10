def set_base_dn
  ENV.has_key?('BASEDN') ? ENV['BASEDN'] : 'o=test'
end

def conn_parameters
  host = ENV.has_key?('HOST') ? ENV['HOST'] : 'localhost'
  port = ENV.has_key?('PORT') ? ENV['PORT'] : 389
  return {:method => :simple, :host => host, :port => port }
end

def auth_parameters
  basedn = set_base_dn
  username = ENV.has_key?('USERNAME') ? "#{basedn},#{ENV['USERNAME']}" : "#{basedn},testadmin"
  password = ENV.has_key?('PASSWORD') ? ENV['PASSWORD'] : 'password'
  return {:username => username, :password => password}
end