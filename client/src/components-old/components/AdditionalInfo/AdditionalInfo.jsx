import React from 'react';

const AdditionalInfo = ({ info }) => {
  
  return info ? <div className="info-box">{info}</div> : null;
};

export default AdditionalInfo;