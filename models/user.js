"use strict";

var bcrypt = require("bcrypt");

module.exports = function(sequelize, DataTypes) {
  var user = sequelize.define("user", {
    email: DataTypes.STRING,
    password: {
        type: DataTypes.STRING,
        validate: {
          len: {
            args: [5, 200],
            msg: "Password must be between 5 and 200 characters long."
          }
        }
      },
    name: DataTypes.STRING
  }, {
    classMethods: {
      associate: function(models) {
        // associations can be defined here
      }
    },
    hooks: {
      beforeCreate: function(data, garbage, callback) {
        var passwordToEncrypt = data.password;
        bcrypt.hash(passwordToEncrypt, 10, function(err, hash) {
          data.password = hash;
          callback(null, data);
        })
      }
    }
  });

  return user;
};
