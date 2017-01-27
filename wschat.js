window.onload = function () {
  var form = document.getElementById('message-form');
  var messageField = document.getElementById('message');
  var messagesList = document.getElementById('messages');
  var socketStatus = document.getElementById('status');
  var closeBtn = document.getElementById('close');
  var socket = new WebSocket('%CHATURL%');
	var hasName = false;

	var askName = function () {
		do
		{
			var name = prompt ("Please enter your name");
			messageField.focus();
		} while (name == null);

		socket.send("/name "+name);
	}

	var sendMessage = function () {
    var message = messageField.value;
    socket.send(message);
		if (message[0] != '/')
		{
			messagesList.innerHTML += '<li class="sent"><span>Sent:</span>' + message + '</li>';
			messagesList.scrollTop = messagesList.scrollHeight;
		}
		messageField.value = '';
	}
	
  socket.onerror = function (error) {
    console.log('WebSocket Error: ' + error);
  };
	
  socket.onopen = function (event) {
		document.getElementById('page-wrapper').className='connected';
    socketStatus.innerHTML = 'Connected to: %CHATURL%';
    socketStatus.className = 'open';
		askName();
  };
	
  socket.onmessage = function (event) {
    var message = event.data;
		if (message[0] == '!')
		{
			var parsed = message.split('!');
			if (parsed.length != 3)
				messagesList.innerHTML += '<li class="error">Unexpected error from server: '+message+'</li>';
			else {
				messagesList.innerHTML += '<li class="error">Error: '+parsed[2]+'</li>';
				if ( ( (parsed[1] == 2) || (parsed[1] == 4)) && (!hasName) )
					askName();
			}
		}
		else if (message[0] == '$')	{
			hasName=true;
			messagesList.innerHTML += '<li class="success">'+message.substr(1)+'</li>';			
		}
		else {
			var sep = message.indexOf('@');
			if (sep == -1)
				messagesList.innerHTML += '<li class="error">Error: Unexpected message</li>';
			else {
				var user = message.substr(0, sep);
				var msg = message.substr(sep+1);
				messagesList.innerHTML += '<li class="received"><span>'+user+'</span>' + msg + '</li>';
			}
		}
		messagesList.scrollTop = messagesList.scrollHeight;

  };
  socket.onclose = function (event) {
		document.getElementById('page-wrapper').className='disconnected';
    socketStatus.innerHTML = 'Disconnected from WebSocket.';
    socketStatus.className = 'closed';
  };

	messageField.onkeypress = function (e) {
		if (e.key=='Enter')
		{
			e.preventDefault();
			sendMessage();
			return false;
		}
		else
			return true;
	}

  form.onsubmit = function (e) {
    e.preventDefault();
		sendMessage();
    return false;
  };
  closeBtn.onclick = function (e) {
    e.preventDefault();
    socket.close();
    return false;
  };
};
