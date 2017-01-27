#pragma once

#include <exception>
#include <string>

/**
   General exceptions will be this type. It's a simple exception class, just with a code
   and message.
 */
class GloveException : public std::exception
{
public:
  /**
   * GloveException
   *
   * @param code      Error code
   * @param message   Error message
   *
   */
  GloveException(const int& code, const std::string &message): _code(code), _message(message)
  {
  }

  virtual ~GloveException() throw ()
  {
  }

  /**
   * Exception message int char*
   */
  const char* what() const throw()
  {
    return _message.c_str();
  }

  /**
   * Exception error code
   *
   * @return error code
   */
  int code() const
  {
    return _code;
  }

protected:
  /** Error code */
  int _code;
  /** Error message  */
  std::string _message;
};

class GloveApiException : public GloveException
{
public:
  GloveApiException(const int& code, const std::string &message): GloveException(code, message)
  {
  }

  virtual ~GloveApiException() throw ()
  {
  }
};
/**
   URI exceptions. Fails addressing a resource
 */
class GloveUriException : public GloveException
{
public:
  /**
   * GloveUriException
   *
   * @param code      Error code
   * @param message   Error message
   *
   */
  GloveUriException(const int& code, const std::string &message): GloveException(code, message)
  {
  }

  virtual ~GloveUriException() throw ()
  {
  }
};

/**
   General exceptions will be this type. It's a simple exception class, just with a code
   and message.
*/
class GloveHttpClientException : public GloveException
{
public:
  /**
   * GloveException
   *
   * @param code      Error code
   * @param message   Error message
   *
   */
  GloveHttpClientException(const int& code, const std::string &message): GloveException(code, message)
  {
  }

  virtual ~GloveHttpClientException() throw ()
  {
  }
};

