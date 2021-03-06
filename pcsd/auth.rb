require 'json'
require 'securerandom'
require 'base64'


# trick with defined? allows to prefill this constants in tests
PCSD_USERS_PATH = PCSD_USERS_CONF_LOCATION unless defined? PCSD_USERS_PATH

class PCSAuth
  # Ruby 1.8.7 doesn't implement SecureRandom.uuid
  def self.uuid
    if defined? SecureRandom.uuid
      return SecureRandom.uuid
    else
      ary = SecureRandom.random_bytes(16).unpack("NnnnnN")
      ary[2] = (ary[2] & 0x0fff) | 0x4000
      ary[3] = (ary[3] & 0x3fff) | 0x8000
      return "%08x-%04x-%04x-%04x-%04x%08x" % ary
    end
  end

  def self.addToken(username, token)
    begin
      password_file = File.open(PCSD_USERS_PATH, File::RDWR|File::CREAT)
      password_file.flock(File::LOCK_EX)
      json = password_file.read()
      users = JSON.parse(json)
    rescue Exception
      $logger.info "Empty file '#{PCSD_USERS_PATH}', creating new file"
      users = []
    end
    user = getUser(users, token)
    if user.nil?
      users << {"username" => username, "token" => token, "creation_date" => Time.now}
    else
      user['username'] = username
    end
    password_file.truncate(0)
    password_file.rewind
    password_file.write(JSON.pretty_generate(users))
    password_file.close()
    return token
  end

  def self.createToken(username)
    return addToken(username, PCSAuth.uuid)
  end

  def self.getUsersGroups(username)
    stdout, stderr, retval = run_cmd(
      getSuperuserAuth(), "id", "-Gn", username
    )
    if retval != 0
      $logger.info(
        "Unable to determine groups of user '#{username}': #{stderr.join(' ').strip}"
      )
      return [false, []]
    end
    return [true, stdout.join(' ').split(nil)]
  end

  def self.isUserAllowedToLogin(username, log_success=true)
    success, groups = getUsersGroups(username)
    if not success
      $logger.info(
        "Failed login by '#{username}' (unable to determine user's groups)"
      )
      return false
    end
    if not groups.include?(ADMIN_GROUP)
      $logger.info(
        "Failed login by '#{username}' (user is not a member of #{ADMIN_GROUP})"
      )
      return false
    end
    if log_success
      $logger.info("Successful login by '#{username}'")
    end
    return true
  end

  def self.getUser(users, token)
    users.each {|u|
      if u["token"] == token
        return u
      end
    }
    return nil
  end

  def self.validToken(token)
    begin
      json = File.read(PCSD_USERS_PATH)
      users = JSON.parse(json)
    rescue
      users = []
    end

    user = getUser(users, token)
    unless user.nil?
      return user['username']
    end
    return false
  end

  def self.loginByToken(cookies)
    auth_user = {}
    if username = validToken(cookies["token"])
      if SUPERUSER == username
        if cookies['CIB_user'] and cookies['CIB_user'].strip != ''
          auth_user[:username] = cookies['CIB_user']
          if cookies['CIB_user_groups'] and cookies['CIB_user_groups'].strip != ''
            auth_user[:usergroups] = cookieUserDecode(
              cookies['CIB_user_groups']
            ).split(nil)
          else
            auth_user[:usergroups] = []
          end
        else
          auth_user[:username] = SUPERUSER
          auth_user[:usergroups] = []
        end
        return auth_user
      else
        auth_user[:username] = username
        success, groups = getUsersGroups(username)
        auth_user[:usergroups] = success ? groups : []
        return auth_user
      end
    end
    return nil
  end

  def self.getSuperuserAuth()
    return {
      :username => SUPERUSER,
      :usergroups => [],
    }
  end

  # Let's be safe about characters in cookie variables and do base64.
  # We cannot do it for CIB_user however to be backward compatible
  # so we at least remove disallowed characters.
  def self.cookieUserSafe(text)
    return text.gsub(/[^!-~]/, '').gsub(';', '')
  end

  def self.cookieUserEncode(text)
    return Base64.encode64(text).gsub("\n", '')
  end

  def self.cookieUserDecode(text)
    return Base64.decode64(text)
  end
end
