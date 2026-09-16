'use strict';

const crypto = require('crypto');
const _ = require('lodash');
const utils = require('@strapi/utils');

const { getAbsoluteAdminUrl, getAbsoluteServerUrl, sanitize, yup, validateYupSchema } = utils;

const forgotPasswordSchema = yup
  .object({
    email: yup.string().email().required(),
  })
  .noUnknown();

const validateForgotPasswordBody = validateYupSchema(forgotPasswordSchema);

const sanitizeUser = (user, ctx) => {
  const { auth } = ctx.state;
  const userSchema = strapi.getModel('plugin::users-permissions.user');

  return sanitize.contentAPI.output(user, userSchema, { auth });
};

module.exports = (plugin) => {
  plugin.controllers.auth.forgotPassword = async (ctx) => {
    const { email } = await validateForgotPasswordBody(ctx.request.body);

    const pluginStore = await strapi.store({ type: 'plugin', name: 'users-permissions' });

    const emailSettings = await pluginStore.get({ key: 'email' });
    const advancedSettings = await pluginStore.get({ key: 'advanced' });

    // Find the user by email.
    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { email: email.toLowerCase() } });

    if (!user || user.blocked) {
      return ctx.send({ ok: true });
    }

    const userInfo = await sanitizeUser(user, ctx);

    const resetPasswordToken = crypto.randomBytes(64).toString('hex');

    const resetPasswordSettings = _.get(emailSettings, 'reset_password.options', {});
    const emailBody = await strapi
      .plugin('users-permissions')
      .service('users-permissions')
      .template(resetPasswordSettings.message, {
        URL: advancedSettings.email_reset_password,
        SERVER_URL: getAbsoluteServerUrl(strapi.config),
        ADMIN_URL: getAbsoluteAdminUrl(strapi.config),
        USER: userInfo,
        TOKEN: resetPasswordToken,
      });

    const emailObject = await strapi
      .plugin('users-permissions')
      .service('users-permissions')
      .template(resetPasswordSettings.object, {
        USER: userInfo,
      });

    const emailToSend = {
      to: user.email,
      from:
        resetPasswordSettings.from.email || resetPasswordSettings.from.name
          ? `${resetPasswordSettings.from.name} <${resetPasswordSettings.from.email}>`
          : undefined,
      replyTo: resetPasswordSettings.response_email,
      subject: emailObject,
      text: emailBody,
      html: emailBody,
    };

    // Save the reset token before sending so it can still be used if delivery fails
    await strapi
      .plugin('users-permissions')
      .service('user')
      .edit(user.id, { resetPasswordToken });

    // Email delivery must never fail the request (mirrors /admin/forgot-password)
    try {
      await strapi.plugin('email').service('email').send(emailToSend);
    } catch (err) {
      strapi.log.warn(`[forgot-password] reset email to ${user.email} failed: ${err.message}`);
    }

    ctx.send({ ok: true });
  };

  return plugin;
};