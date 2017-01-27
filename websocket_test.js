window.onload = function () {
  var form = document.getElementById('message-form');
  var messageField = document.getElementById('message');
  var messagesList = document.getElementById('messages');
  var socketStatus = document.getElementById('status');
  var closeBtn = document.getElementById('close');
  var socket = new WebSocket('ws://localhost:8080/echo/');

  socket.onerror = function (error) {
    console.log('WebSocket Error: ' + error);
  };
  socket.onopen = function (event) {
		document.getElementById('page-wrapper').className='connected';
    socketStatus.innerHTML = 'Connected to: ws://localhost:8080/echo';
    socketStatus.className = 'open';
  };
  socket.onmessage = function (event) {
    var message = event.data;
    messagesList.innerHTML += '<li class="received"><span>Received:</span>' + message + '</li>';
		messagesList.scrollTop = messagesList.scrollHeight;		
  };
  socket.onclose = function (event) {
		document.getElementById('page-wrapper').className='disconnected';
    socketStatus.innerHTML = 'Disconnected from WebSocket.';
    socketStatus.className = 'closed';
  };
  form.onsubmit = function (e) {
    e.preventDefault();
    var message = messageField.value;
    socket.send(message);
    messagesList.innerHTML += '<li class="sent"><span>Sent:</span>' + message + '</li>';
		messagesList.scrollTop = messagesList.scrollHeight;
    messageField.value = '';
    return false;
  };
  closeBtn.onclick = function (e) {
    e.preventDefault();
    socket.close();
    return false;
  };
};
