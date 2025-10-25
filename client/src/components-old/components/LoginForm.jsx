import React from 'react';

const LoginForm = () => {
  return (
    <div>
      <h2>Login Form</h2>
      <form>
        <div className='form-group'>
          <input type="text" placeholder='Username' required />
        </div>

        <div className='form-group'>
          <input type="password" placeholder='Password' required />
        </div>

        <button className='frontend-button' type='submit'>Login</button>
      </form>
    </div>
  );
};

export default LoginForm;